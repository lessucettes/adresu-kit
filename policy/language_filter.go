// policy/language_filter.go
package policy

import (
	"adresu-kit/config"
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"

	lru "github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/nbd-wtf/go-nostr"
	"github.com/pemistahl/lingua-go"
)

var (
	globalDetectorOnce  sync.Once
	globalDetector      lingua.LanguageDetector
	buildLookupOnce     sync.Once
	languageLookupMap   map[string]lingua.Language
	contentCleanerRegex *regexp.Regexp
)

func init() {
	const cleanerPattern = `((https?|wss?)://|www\.|ww\.)[^\s/?.#-]+\S*|[a-zA-Z0-9.!$%&’+_\x60\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,64}|nostr:[a-z0-9]+|#\S+|[a-zA-Z]*[0-9]+[a-zA-Z0-9]*`
	contentCleanerRegex = regexp.MustCompile(cleanerPattern)
}

type LanguageFilter struct {
	cfg               *config.LanguageFilterConfig
	detector          lingua.LanguageDetector
	allowedLangs      map[lingua.Language]struct{}
	allowedKinds      map[int]struct{}
	approvedCache     *lru.LRU[string, struct{}]
	thresholds        map[lingua.Language]map[lingua.Language]float64
	defaultThresholds map[lingua.Language]float64
}

func NewLanguageFilter(cfg *config.LanguageFilterConfig, detector lingua.LanguageDetector) (*LanguageFilter, []string, error) {
	if !cfg.Enabled {
		return &LanguageFilter{cfg: cfg}, nil, nil
	}
	if detector == nil {
		return nil, nil, errors.New("language filter enabled but detector is nil")
	}

	buildLookupOnce.Do(buildLanguageLookupMap)

	var warnings []string

	allowedMap := make(map[lingua.Language]struct{}, len(cfg.AllowedLanguages))
	for _, langStr := range cfg.AllowedLanguages {
		if lang, ok := languageLookupMap[strings.ToLower(langStr)]; ok {
			allowedMap[lang] = struct{}{}
		} else {
			warnings = append(warnings, fmt.Sprintf("Unsupported language name or ISO code in config; ignored: %s", langStr))
		}
	}

	allowedKinds := make(map[int]struct{}, len(cfg.KindsToCheck))
	for _, k := range cfg.KindsToCheck {
		allowedKinds[k] = struct{}{}
	}

	thresholds := make(map[lingua.Language]map[lingua.Language]float64)
	defaultThresholds := make(map[lingua.Language]float64)

	for primaryStr, similarMap := range cfg.PrimaryAcceptThreshold {
		primaryLang, ok := languageLookupMap[strings.ToLower(primaryStr)]
		if !ok {
			warnings = append(warnings, fmt.Sprintf("Primary language in threshold rules not found, skipping rule for: %s", primaryStr))
			continue
		}
		thresholds[primaryLang] = make(map[lingua.Language]float64)
		for similarStr, confidence := range similarMap {
			if strings.ToLower(similarStr) == "default" {
				defaultThresholds[primaryLang] = confidence
			} else if similarLang, ok := languageLookupMap[strings.ToLower(similarStr)]; ok {
				thresholds[primaryLang][similarLang] = confidence
			} else {
				warnings = append(warnings, fmt.Sprintf("Unsupported similar language in threshold rule; ignored: primary=%s, similar=%s", primaryStr, similarStr))
			}
		}
	}

	var cache *lru.LRU[string, struct{}]
	if cfg.ApprovedCacheTTL > 0 && cfg.ApprovedCacheSize > 0 {
		cache = lru.NewLRU[string, struct{}](cfg.ApprovedCacheSize, nil, cfg.ApprovedCacheTTL)
	}

	filter := &LanguageFilter{
		cfg:               cfg,
		detector:          detector,
		allowedLangs:      allowedMap,
		allowedKinds:      allowedKinds,
		approvedCache:     cache,
		thresholds:        thresholds,
		defaultThresholds: defaultThresholds,
	}

	return filter, warnings, nil
}

func (f *LanguageFilter) Match(ctx context.Context, event *nostr.Event, meta map[string]any) (bool, error) {
	if !f.cfg.Enabled || len(f.allowedLangs) == 0 {
		return true, nil
	}
	if _, ok := f.allowedKinds[event.Kind]; !ok {
		return true, nil
	}
	if f.cfg.MinLengthForCheck > 0 && len(event.Content) < f.cfg.MinLengthForCheck {
		return true, nil
	}
	if f.approvedCache != nil {
		if _, ok := f.approvedCache.Get(event.PubKey); ok {
			return true, nil
		}
	}

	cleanedContent := contentCleanerRegex.ReplaceAllString(event.Content, "")
	if len(cleanedContent) < f.cfg.MinLengthForCheck {
		return true, nil
	}

	detectedLang, detected := f.detector.DetectLanguageOf(cleanedContent)
	if !detected {
		return false, errors.New("blocked: language could not be determined")
	}

	if _, isAllowed := f.allowedLangs[detectedLang]; isAllowed {
		if f.approvedCache != nil {
			f.approvedCache.Add(event.PubKey, struct{}{})
		}
		if meta != nil {
			meta["language"] = detectedLang.String()
		}
		return true, nil
	}

	for primaryLang, similarLangsMap := range f.thresholds {
		threshold, hasRule := similarLangsMap[detectedLang]
		if !hasRule {
			threshold, hasRule = f.defaultThresholds[primaryLang]
		}
		if hasRule {
			confidence := f.detector.ComputeLanguageConfidence(cleanedContent, primaryLang)
			if confidence > threshold {
				if f.approvedCache != nil {
					f.approvedCache.Add(event.PubKey, struct{}{})
				}
				if meta != nil {
					meta["language"] = detectedLang.String()
				}
				return true, nil
			}
		}
	}

	return false, fmt.Errorf("blocked: language '%s' is not allowed", detectedLang.String())
}

func GetGlobalDetector() lingua.LanguageDetector {
	globalDetectorOnce.Do(func() {
		globalDetector = lingua.NewLanguageDetectorBuilder().
			FromAllLanguages().
			WithLowAccuracyMode().
			WithPreloadedLanguageModels().
			Build()
	})
	return globalDetector
}

func buildLanguageLookupMap() {
	allLangs := lingua.AllLanguages()
	languageLookupMap = make(map[string]lingua.Language, len(allLangs)*3)

	for _, lang := range allLangs {
		languageLookupMap[strings.ToLower(lang.String())] = lang
		languageLookupMap[strings.ToLower(lang.IsoCode639_1().String())] = lang
		languageLookupMap[strings.ToLower(lang.IsoCode639_3().String())] = lang
	}
}
