// policy/tags_filter.go
package policy

import (
	"context"
	"fmt"

	"github.com/lessucettes/adresu-kit/config"
	"github.com/nbd-wtf/go-nostr"
)

type TagsFilter struct{ kindToRule map[int]processedTagRule }

// processedTagRule holds a pre-compiled, ready-to-use version of a rule.
type processedTagRule struct {
	source       *config.TagRule
	requiredTags map[string]struct{}
	maxTagCounts map[string]int
}

func NewTagsFilter(cfg *config.TagsFilterConfig) (*TagsFilter, []string, error) {
	kindMap := make(map[int]processedTagRule)
	if cfg != nil {
		for i := range cfg.Rules {
			rule := &cfg.Rules[i]
			processed := processedTagRule{
				source:       rule,
				requiredTags: make(map[string]struct{}),
				maxTagCounts: make(map[string]int),
			}
			if len(rule.RequiredTags) > 0 {
				for _, req := range rule.RequiredTags {
					processed.requiredTags[req] = struct{}{}
				}
			}
			if len(rule.MaxTagCounts) > 0 {
				for key, val := range rule.MaxTagCounts {
					processed.maxTagCounts[key] = val
				}
			}
			for _, kind := range rule.Kinds {
				kindMap[kind] = processed
			}
		}
	}

	filter := &TagsFilter{kindToRule: kindMap}

	return filter, nil, nil
}

func (f *TagsFilter) Match(ctx context.Context, event *nostr.Event, meta map[string]any) (bool, error) {
	processedRule, exists := f.kindToRule[event.Kind]
	if !exists {
		return true, nil
	}
	rule := processedRule.source

	if rule.MaxTags != nil && len(event.Tags) > *rule.MaxTags {
		return false, fmt.Errorf("blocked: too many tags for %s (got %d, max %d)",
			rule.Description, len(event.Tags), *rule.MaxTags)
	}

	if len(processedRule.requiredTags) > 0 || len(processedRule.maxTagCounts) > 0 {
		requiredFound := make(map[string]bool, len(processedRule.requiredTags))
		specificTagCounts := make(map[string]int, len(processedRule.maxTagCounts))

		for _, tag := range event.Tags {
			if len(tag) == 0 || tag[0] == "" {
				continue
			}
			tagName := tag[0]

			if _, ok := processedRule.maxTagCounts[tagName]; ok {
				specificTagCounts[tagName]++
			}
			if _, ok := processedRule.requiredTags[tagName]; ok {
				requiredFound[tagName] = true
			}
		}

		for reqTag := range processedRule.requiredTags {
			if !requiredFound[reqTag] {
				return false, fmt.Errorf("blocked: missing required tag '%s' for %s", reqTag, rule.Description)
			}
		}

		for tagName, limit := range processedRule.maxTagCounts {
			count := specificTagCounts[tagName]
			if count > limit {
				return false, fmt.Errorf("blocked: too many '%s' tags for %s (got %d, max %d)",
					tagName, rule.Description, count, limit)
			}
		}
	}

	return true, nil
}
