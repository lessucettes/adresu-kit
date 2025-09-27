// policy/size_filter.go
package policy

import (
	"adresu-kit/config"
	"context"
	"encoding/json"
	"fmt"

	"github.com/nbd-wtf/go-nostr"
)

type SizeFilter struct {
	cfg        *config.SizeFilterConfig
	kindToRule map[int]*config.SizeRule
}

func NewSizeFilter(cfg *config.SizeFilterConfig) (*SizeFilter, []string, error) {
	kindMap := make(map[int]*config.SizeRule, len(cfg.Rules))
	if cfg != nil {
		for i := range cfg.Rules {
			rule := &cfg.Rules[i]
			for _, kind := range rule.Kinds {
				kindMap[kind] = rule
			}
		}
	}

	filter := &SizeFilter{cfg: cfg, kindToRule: kindMap}

	return filter, nil, nil
}

func (f *SizeFilter) Match(ctx context.Context, event *nostr.Event, meta map[string]any) (bool, error) {
	maxSize := f.cfg.DefaultMaxSize
	description := "default event"
	if rule, ok := f.kindToRule[event.Kind]; ok {
		maxSize = rule.MaxSize
		description = rule.Description
	}

	if maxSize == 0 {
		return true, nil
	}

	raw, err := json.Marshal(event)
	if err != nil {
		return false, fmt.Errorf("internal: failed to marshal event for size check: %w", err)
	}
	size := len(raw)

	if size > maxSize {
		return false, fmt.Errorf("blocked: event size %d bytes exceeds limit of %d for %s", size, maxSize, description)
	}

	return true, nil
}
