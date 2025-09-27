package policy

import (
	"context"
	"fmt"
	"regexp"

	"github.com/lessucettes/adresu-kit/config"
	"github.com/nbd-wtf/go-nostr"
)

type compiledKeywordRule struct {
	source      string
	description string
	regex       *regexp.Regexp
}

type KeywordFilter struct {
	enabled     bool
	kindToRules map[int][]compiledKeywordRule
}

func NewKeywordFilter(cfg *config.KeywordFilterConfig) (*KeywordFilter, []string, error) {
	if !cfg.Enabled {
		return &KeywordFilter{enabled: false}, nil, nil
	}

	kindMap := make(map[int][]compiledKeywordRule)
	for _, rule := range cfg.Rules {
		for _, word := range rule.Words {
			compiled, err := regexp.Compile(`(?i)\b` + regexp.QuoteMeta(word) + `\b`)
			if err != nil {
				return nil, nil, fmt.Errorf("internal error compiling keyword '%s': %w", word, err)
			}
			ckr := compiledKeywordRule{
				source:      word,
				description: rule.Description,
				regex:       compiled,
			}
			for _, kind := range rule.Kinds {
				kindMap[kind] = append(kindMap[kind], ckr)
			}
		}

		for _, rx := range rule.Regexps {
			compiled, err := regexp.Compile(rx)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to compile user regexp '%s' for rule '%s': %w", rx, rule.Description, err)
			}
			ckr := compiledKeywordRule{
				source:      rx,
				description: rule.Description,
				regex:       compiled,
			}
			for _, kind := range rule.Kinds {
				kindMap[kind] = append(kindMap[kind], ckr)
			}
		}
	}

	filter := &KeywordFilter{
		enabled:     cfg.Enabled,
		kindToRules: kindMap,
	}

	return filter, nil, nil
}

func (f *KeywordFilter) Match(ctx context.Context, event *nostr.Event, meta map[string]any) (bool, error) {
	if !f.enabled {
		return true, nil
	}

	rules, exists := f.kindToRules[event.Kind]
	if !exists {
		return true, nil
	}

	for _, rule := range rules {
		if rule.regex.MatchString(event.Content) {
			return false, fmt.Errorf("blocked: content contains forbidden pattern ('%s' from rule '%s')", rule.source, rule.description)
		}
	}

	return true, nil
}
