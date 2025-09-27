// policy/freshness_filter.go
package policy

import (
	"adresu-kit/config"
	"context"
	"fmt"
	"time"

	"github.com/nbd-wtf/go-nostr"
)

type timeLimits struct {
	MaxPast   time.Duration
	MaxFuture time.Duration
}

type FreshnessFilter struct {
	cfg         *config.FreshnessFilterConfig
	rulesByKind map[int]timeLimits
}

func NewFreshnessFilter(cfg *config.FreshnessFilterConfig) (*FreshnessFilter, []string, error) {
	rulesByKind := make(map[int]timeLimits)
	if cfg != nil {
		for _, rule := range cfg.Rules {
			limits := timeLimits{
				MaxPast:   rule.MaxPast,
				MaxFuture: rule.MaxFuture,
			}
			for _, kind := range rule.Kinds {
				rulesByKind[kind] = limits
			}
		}
	}

	filter := &FreshnessFilter{
		cfg:         cfg,
		rulesByKind: rulesByKind,
	}

	return filter, nil, nil
}

func (f *FreshnessFilter) Match(ctx context.Context, event *nostr.Event, meta map[string]any) (bool, error) {
	maxPast, maxFuture := f.cfg.DefaultMaxPast, f.cfg.DefaultMaxFuture

	if limits, ok := f.rulesByKind[event.Kind]; ok {
		maxPast = limits.MaxPast
		maxFuture = limits.MaxFuture
	}

	now := time.Now()
	createdAt := event.CreatedAt.Time()

	age := now.Sub(createdAt)
	futureOffset := createdAt.Sub(now)

	if maxPast > 0 && age > maxPast {
		return false, fmt.Errorf("blocked: event is too old (age: %s)", age.Round(time.Second))
	}

	if maxFuture > 0 && futureOffset > maxFuture {
		return false, fmt.Errorf("blocked: event timestamp is in the future (offset: %s)", futureOffset.Round(time.Second))
	}

	return true, nil
}
