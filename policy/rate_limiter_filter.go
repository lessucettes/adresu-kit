package policy

import (
	"context"
	"fmt"
	"strconv"
	"time"

	lru "github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/lessucettes/adresu-kit/config"
	"github.com/nbd-wtf/go-nostr"
	"golang.org/x/time/rate"
)

type processedRateRule struct {
	rule *config.RateLimitRule
	id   string
}

type RateLimiterFilter struct {
	cfg        *config.RateLimiterConfig
	limiters   *lru.LRU[string, *rate.Limiter]
	kindToRule map[int]processedRateRule
}

func NewRateLimiterFilter(cfg *config.RateLimiterConfig) (*RateLimiterFilter, []string, error) {
	size := cfg.CacheSize
	if size <= 0 {
		size = 65536
	}
	ttl := cfg.TTL
	if ttl <= 0 {
		ttl = time.Minute * 10
	}

	cache := lru.NewLRU[string, *rate.Limiter](size, nil, ttl)
	kindMap := make(map[int]processedRateRule, len(cfg.Rules))

	for i := range cfg.Rules {
		rule := &cfg.Rules[i]
		processed := processedRateRule{
			rule: rule,
			id:   "rule-" + strconv.Itoa(i),
		}
		for _, kind := range rule.Kinds {
			kindMap[kind] = processed
		}
	}

	filter := &RateLimiterFilter{
		cfg:        cfg,
		limiters:   cache,
		kindToRule: kindMap,
	}

	return filter, nil, nil
}

func (f *RateLimiterFilter) Match(ctx context.Context, event *nostr.Event, meta map[string]any) (bool, error) {
	if !f.cfg.Enabled {
		return true, nil
	}

	var currentRate float64
	var currentBurst int
	var ruleID string
	var ruleDescription string

	if processed, exists := f.kindToRule[event.Kind]; exists {
		currentRate = processed.rule.Rate
		currentBurst = processed.rule.Burst
		ruleID = processed.id
		ruleDescription = processed.rule.Description
	} else {
		currentRate = f.cfg.DefaultRate
		currentBurst = f.cfg.DefaultBurst
		ruleID = "default"
		ruleDescription = "default"
	}

	if currentRate <= 0 {
		return true, nil
	}

	var userKeys []string
	remoteIP, _ := meta["remote_ip"].(string)

	switch f.cfg.By {
	case config.RateByIP:
		if remoteIP != "" {
			userKeys = append(userKeys, "ip:"+remoteIP)
		}
	case config.RateByPubKey:
		if event.PubKey != "" {
			userKeys = append(userKeys, "pk:"+event.PubKey)
		}
	case config.RateByBoth:
		if remoteIP != "" {
			userKeys = append(userKeys, "ip:"+remoteIP)
		}
		if event.PubKey != "" {
			userKeys = append(userKeys, "pk:"+event.PubKey)
		}
	}

	for _, userKey := range userKeys {
		cacheKey := fmt.Sprintf("%s:%s", ruleID, userKey)
		limiter := f.getLimiter(cacheKey, currentRate, currentBurst)
		if !limiter.Allow() {
			return false, fmt.Errorf("blocked: rate limit exceeded for %s", ruleDescription)
		}
	}
	return true, nil
}

func (f *RateLimiterFilter) getLimiter(key string, r float64, b int) *rate.Limiter {
	if limiter, ok := f.limiters.Get(key); ok {
		return limiter
	}
	limiter := rate.NewLimiter(rate.Limit(r), b)
	f.limiters.Add(key, limiter)
	return limiter
}
