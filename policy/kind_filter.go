package policy

import (
	"context"
	"fmt"

	"github.com/lessucettes/adresu-kit/config"
	"github.com/nbd-wtf/go-nostr"
)

type KindFilter struct {
	allowed, denied map[int]struct{}
}

func NewKindFilter(cfg *config.KindFilterConfig) (*KindFilter, []string, error) {
	deniedMap := make(map[int]struct{}, len(cfg.DeniedKinds))
	for _, kind := range cfg.DeniedKinds {
		deniedMap[kind] = struct{}{}
	}
	var allowedMap map[int]struct{}
	if len(cfg.AllowedKinds) > 0 {
		allowedMap = make(map[int]struct{}, len(cfg.AllowedKinds))
		for _, kind := range cfg.AllowedKinds {
			allowedMap[kind] = struct{}{}
		}
	}

	filter := &KindFilter{allowed: allowedMap, denied: deniedMap}

	return filter, nil, nil
}

func (f *KindFilter) Match(ctx context.Context, event *nostr.Event, meta map[string]any) (bool, error) {
	// Denylist has priority.
	if _, isDenied := f.denied[event.Kind]; isDenied {
		return false, fmt.Errorf("blocked: event kind %d is on the denylist", event.Kind)
	}
	if f.allowed != nil {
		if _, isAllowed := f.allowed[event.Kind]; !isAllowed {
			return false, fmt.Errorf("blocked: event kind %d is not on the allowlist", event.Kind)
		}
	}
	return true, nil
}
