# Adresu Kit

A library of reusable components for embedding Nostr policy logic.

This library contains a collection of stateless and stateful filters for processing and enforcing policies on Nostr events.

---

## 🚀 Installation

```bash
go get https://github.com/lessucettes/adresu-kit@latest
```

-----

## ✨ Usage

Each filter is created via a constructor that accepts a configuration struct. The `Match` method returns a structured `FilterResult` containing the decision, reason, and other metadata.

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/nbd-wtf/go-nostr"

	"github.com/lessucettes/adresu-kit/config"
	"github.com/lessucettes/adresu-kit/policy"
)

func main() {
	// 1. Configure the filter
	cfg := &config.KindFilterConfig{DeniedKinds: []int{4}}

	// 2. Create a new filter instance.
	// Constructors return only the filter and a critical error.
	// Configuration warnings are logged automatically during creation.
	kindFilter, err := policy.NewKindFilter(cfg)
	if err != nil {
		log.Fatalf("Failed to create filter: %v", err)
	}

	// 3. Create a sample event
	event := &nostr.Event{Kind: 4}

	// 4. Match the event against the filter.
	// The Match method returns a structured FilterResult and a critical error.
	res, err := kindFilter.Match(context.Background(), event, nil)
	if err != nil {
		// This handles critical errors within the filter's execution.
		log.Fatalf("Filter failed to execute: %v", err)
	}

	// 5. Check the result
	if !res.Allowed {
		// The result struct contains the decision, filter name, reason, and duration.
		fmt.Printf("Filter '%s' rejected the event. Reason: %s\n", res.Filter, res.Reason)
		// Example output: Filter 'KindFilter' rejected the event. Reason: kind_4_denied
	} else {
		fmt.Printf("Filter '%s' allowed the event in %s.\n", res.Filter, res.Duration)
	}
}
```

-----

## 🛡️ Filters

### Stateless Filters

Decision is based only on the event's content.

  * **KindFilter**: Filters by `kind` based on allow/deny lists.
  * **FreshnessFilter**: Filters by `created_at` timestamp against `max_past` and `max_future` durations.
  * **SizeFilter**: Filters by the total byte size of the marshaled event.
  * **TagsFilter**: Enforces limits on tag count, required tags, and per-tag-name counts.
  * **KeywordFilter**: Filters by content using simple word matching or regular expressions.

### Stateful Filters

Decision is based on an internal state (LRU cache) that tracks patterns over time.

  * **LanguageFilter**: Filters by language. Caches authors who pass the check.
  * **RateLimiterFilter**: Limits event frequency per `pubkey`, `ip`, or both.
  * **RepostAbuseFilter**: Tracks the repost-to-original-post ratio for users.
  * **EphemeralChatFilter**: Applies a set of strict rules for chat kinds (flood delay, caps ratio, PoW fallback).
  * **EmergencyFilter**: A DDoS mitigation filter that rate-limits new, unseen pubkeys.

-----

## ⚙️ Utilities

The `nip` package contains helpers for specific NIPs.

  * **NIP-13**: `nip.IsPoWValid()` for validating Proof-of-Work.
  * **NIP-26**: `nip.ValidateDelegation()` for validating delegated events.

-----

## 📄 License

This project is licensed under the MIT License. See the `LICENSE` file for details.
