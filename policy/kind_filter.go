// policy/kind_filter.go
package policy

import (
	"context"
	"fmt"

	"github.com/nbd-wtf/go-nostr"
)

type KindFilter struct {
	allowed, denied map[int]struct{}
}

func NewKindFilter(allowedKinds, deniedKinds []int) (*KindFilter, []string, error) {
	deniedMap := make(map[int]struct{}, len(deniedKinds))
	for _, kind := range deniedKinds {
		deniedMap[kind] = struct{}{}
	}
	var allowedMap map[int]struct{}
	if len(allowedKinds) > 0 {
		allowedMap = make(map[int]struct{}, len(allowedKinds))
		for _, kind := range allowedKinds {
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
