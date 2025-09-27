// policy/ephemeral_chat_filter.go
package policy

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"
	"unicode"

	lru "github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/lessucettes/adresu-kit/config"
	"github.com/lessucettes/adresu-kit/nip"
	"github.com/nbd-wtf/go-nostr"
	"golang.org/x/time/rate"
)

type EphemeralChatFilter struct {
	cfg        *config.EphemeralChatFilterConfig
	zalgoRegex *regexp.Regexp
	wordRegex  *regexp.Regexp
	lastSeen   *lru.LRU[string, time.Time]
	limiters   *lru.LRU[string, *rate.Limiter]
}

func NewEphemeralChatFilter(cfg *config.EphemeralChatFilterConfig) (*EphemeralChatFilter, []string, error) {
	if !cfg.Enabled {
		return &EphemeralChatFilter{cfg: cfg}, nil, nil
	}

	var zalgoRegex, wordRegex *regexp.Regexp
	var err error

	if cfg.BlockZalgo {
		zalgoRegex = regexp.MustCompile("[\u0300-\u036F\u1AB0-\u1AFF\u1DC0-\u1DFF\u20D0-\u20FF\uFE20-\uFE2F]")
	}
	if cfg.MaxWordLength > 0 {
		wordRegex, err = regexp.Compile(fmt.Sprintf(`\S{%d,}`, cfg.MaxWordLength))
		if err != nil {
			return nil, nil, fmt.Errorf("invalid max_word_length generates bad regexp: %w", err)
		}
	}

	size := cfg.CacheSize
	if size <= 0 {
		size = 10000
	}
	lastSeen := lru.NewLRU[string, time.Time](size, nil, 5*time.Minute)
	limiters := lru.NewLRU[string, *rate.Limiter](size, nil, 15*time.Minute)

	filter := &EphemeralChatFilter{
		cfg:        cfg,
		zalgoRegex: zalgoRegex,
		wordRegex:  wordRegex,
		lastSeen:   lastSeen,
		limiters:   limiters,
	}

	return filter, nil, nil
}

func (f *EphemeralChatFilter) Match(ctx context.Context, event *nostr.Event, meta map[string]any) (bool, error) {
	if !f.cfg.Enabled || !slices.Contains(f.cfg.Kinds, event.Kind) {
		return true, nil
	}

	if f.lastSeen != nil && f.cfg.MinDelay > 0 {
		now := time.Now()
		if last, ok := f.lastSeen.Get(event.PubKey); ok {
			delay := now.Sub(last)
			if delay < f.cfg.MinDelay {
				return false, fmt.Errorf("blocked: posting too frequently in chat (delay: %s, limit: %s)", delay.Round(time.Millisecond), f.cfg.MinDelay)
			}
		}
		f.lastSeen.Add(event.PubKey, now)
	}

	content := event.Content

	if f.cfg.MaxCapsRatio > 0 {
		letters, caps := 0, 0
		for _, r := range content {
			if unicode.IsLetter(r) {
				letters++
				if unicode.IsUpper(r) {
					caps++
				}
			}
		}
		minLetters := f.cfg.MinLettersForCapsCheck
		if minLetters <= 0 {
			minLetters = 20
		}
		if letters > minLetters {
			ratio := float64(caps) / float64(letters)
			if ratio > f.cfg.MaxCapsRatio {
				return false, fmt.Errorf("blocked: excessive use of capital letters (ratio: %.2f, limit: %.2f)", ratio, f.cfg.MaxCapsRatio)
			}
		}
	}

	if f.cfg.MaxRepeatChars > 0 {
		runes := []rune(content)
		if len(runes) >= f.cfg.MaxRepeatChars {
			count := 1
			for i := 1; i < len(runes); i++ {
				if runes[i] == runes[i-1] {
					count++
				} else {
					count = 1
				}
				if count >= f.cfg.MaxRepeatChars {
					return false, fmt.Errorf("blocked: excessive character repetition (count: %d, limit: %d)", count, f.cfg.MaxRepeatChars)
				}
			}
		}
	}

	if f.wordRegex != nil && f.wordRegex.MatchString(content) {
		return false, fmt.Errorf("blocked: message contains words that are too long (limit: %d)", f.cfg.MaxWordLength)
	}

	if f.zalgoRegex != nil && f.zalgoRegex.MatchString(content) {
		return false, errors.New("blocked: message contains Zalgo text")
	}

	limiter := f.getLimiter(event.PubKey)
	if limiter.Allow() {
		return true, nil
	}

	if nip.IsPoWValid(event, f.cfg.RequiredPoWOnLimit) {
		return true, nil
	}

	return false, fmt.Errorf("blocked: chat rate limit exceeded. Attach PoW of difficulty %d to send", f.cfg.RequiredPoWOnLimit)
}

func (f *EphemeralChatFilter) getLimiter(key string) *rate.Limiter {
	if limiter, ok := f.limiters.Get(key); ok {
		return limiter
	}
	limiter := rate.NewLimiter(rate.Limit(f.cfg.RateLimitRate), f.cfg.RateLimitBurst)
	f.limiters.Add(key, limiter)
	return limiter
}
