// policy/repost_abuse_filter.go
package policy

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"adresu-kit/config"

	lru "github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/nbd-wtf/go-nostr"
)

// UserActivityStats tracks per-pubkey posting behavior.
type UserActivityStats struct {
	OriginalPosts int
	Reposts       int
	LastEventTime time.Time
}

// RepostAbuseFilter observes user behavior and rejects users who mostly repost.
type RepostAbuseFilter struct {
	mu    sync.Mutex
	stats *lru.LRU[string, *UserActivityStats]
	cfg   *config.RepostAbuseFilterConfig
}

var nip21Re = regexp.MustCompile(`\b(naddr1|nevent1|note1)[0-9a-z]+\b`)

func NewRepostAbuseFilter(cfg *config.RepostAbuseFilterConfig) (*RepostAbuseFilter, []string, error) {
	size := cfg.CacheSize
	cache := lru.NewLRU[string, *UserActivityStats](size, nil, cfg.CacheTTL)

	if cfg.MaxRatio < 0 {
		cfg.MaxRatio = 0
	} else if cfg.MaxRatio > 1 {
		cfg.MaxRatio = 1
	}

	filter := &RepostAbuseFilter{
		stats: cache,
		cfg:   cfg,
	}

	return filter, nil, nil
}

func (f *RepostAbuseFilter) Match(ctx context.Context, event *nostr.Event, meta map[string]any) (bool, error) {
	if !f.cfg.Enabled {
		return true, nil
	}
	if event.Kind != nostr.KindTextNote && event.Kind != nostr.KindRepost && event.Kind != nostr.KindGenericRepost {
		return true, nil
	}

	f.mu.Lock()
	stats, ok := f.stats.Get(event.PubKey)
	if !ok || stats == nil {
		stats = &UserActivityStats{}
	} else if f.cfg.ResetDuration > 0 && !stats.LastEventTime.IsZero() {
		if time.Since(stats.LastEventTime) > f.cfg.ResetDuration {
			stats.OriginalPosts, stats.Reposts = 0, 0
		}
	}
	statsCopy := *stats
	f.mu.Unlock()

	isRepost, _ := f.isRepostNIP18(event)

	var rejectionError error
	if isRepost {
		total := statsCopy.OriginalPosts + statsCopy.Reposts
		if total >= f.cfg.MinEvents {
			predictedReposts := statsCopy.Reposts + 1
			predictedTotal := total + 1
			var currentRatio float64
			if predictedTotal > 0 {
				currentRatio = float64(predictedReposts) / float64(predictedTotal)
			}
			if currentRatio >= f.cfg.MaxRatio {
				ratioPercent := currentRatio * 100
				limitPercent := f.cfg.MaxRatio * 100
				rejectionError = fmt.Errorf(
					"blocked: too many reposts. Your repost ratio would be %.1f%%, the limit is %.1f%%",
					ratioPercent, limitPercent,
				)
			}
		}
	}

	f.mu.Lock()
	fresh, ok := f.stats.Get(event.PubKey)
	if !ok || fresh == nil {
		fresh = &UserActivityStats{}
	}
	if f.cfg.ResetDuration > 0 && !fresh.LastEventTime.IsZero() {
		if time.Since(fresh.LastEventTime) > f.cfg.ResetDuration {
			fresh.OriginalPosts, fresh.Reposts = 0, 0
		}
	}
	if rejectionError == nil || f.cfg.CountRejectAsActivity {
		fresh.LastEventTime = time.Now()
	}
	if rejectionError == nil {
		if isRepost {
			fresh.Reposts++
		} else {
			fresh.OriginalPosts++
		}
	}
	f.stats.Add(event.PubKey, fresh)
	f.mu.Unlock()

	if rejectionError != nil {
		return false, rejectionError
	}
	return true, nil
}

// isRepostNIP18 classifies events as reposts per NIP-18.
// Returns (true, classification) if it's a repost, where classification is one of
// "kind6", "kind16", "quote1". Otherwise returns (false, "").
func (f *RepostAbuseFilter) isRepostNIP18(ev *nostr.Event) (bool, string) {
	switch ev.Kind {
	case nostr.KindRepost: // 6
		return true, "kind6"
	case 16: // generic repost
		return true, "kind16"
	case nostr.KindTextNote: // 1
		// Quote reposts: kind 1 with a 'q' tag.
		if hasTag(ev, "q") {
			// Optionally require NIP-21 ref in content for stricter quote detection.
			if !f.cfg.RequireNIP21InQuote || contentHasNIP21Ref(ev.Content) {
				return true, "quote1"
			}
		}
	}
	return false, ""
}

func hasTag(ev *nostr.Event, tagName string) bool {
	for _, t := range ev.Tags {
		if len(t) > 0 && strings.EqualFold(t[0], tagName) {
			return true
		}
	}
	return false
}

func contentHasNIP21Ref(s string) bool {
	return nip21Re.MatchString(s)
}
