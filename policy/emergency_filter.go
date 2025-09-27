// policy/emergency_filter.go
package policy

import (
	"adresu-kit/config"
	"context"
	"errors"
	"net"

	lru "github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/nbd-wtf/go-nostr"
	"golang.org/x/time/rate"
)

type EmergencyFilter struct {
	newKeyLimiter *rate.Limiter
	recentSeen    *lru.LRU[string, struct{}]

	perIPEnabled  bool
	perIPLimiters *lru.LRU[string, *rate.Limiter]
	perIPRate     rate.Limit
	perIPBurst    int

	ipv4Prefix int
	ipv6Prefix int
}

func NewEmergencyFilter(cfg *config.EmergencyFilterConfig) (*EmergencyFilter, []string, error) {
	if cfg == nil || !cfg.Enabled {
		return &EmergencyFilter{}, nil, nil
	}

	filter := &EmergencyFilter{
		newKeyLimiter: rate.NewLimiter(rate.Limit(cfg.NewKeysRate), cfg.NewKeysBurst),
		recentSeen:    lru.NewLRU[string, struct{}](cfg.CacheSize, nil, cfg.TTL),
	}

	if cfg.PerIP.Enabled {
		filter.perIPEnabled = true
		filter.perIPLimiters = lru.NewLRU[string, *rate.Limiter](cfg.PerIP.CacheSize, nil, cfg.PerIP.TTL)
		filter.perIPRate = rate.Limit(cfg.PerIP.Rate)
		filter.perIPBurst = cfg.PerIP.Burst
		filter.ipv4Prefix = cfg.PerIP.IPv4Prefix
		filter.ipv6Prefix = cfg.PerIP.IPv6Prefix
	}

	return filter, nil, nil
}

func (f *EmergencyFilter) Match(ctx context.Context, ev *nostr.Event, meta map[string]any) (bool, error) {
	if f.newKeyLimiter == nil {
		return true, nil
	}
	pk := ev.PubKey
	if pk == "" {
		return true, nil
	}
	if _, ok := f.recentSeen.Get(pk); ok {
		return true, nil
	}

	if f.perIPEnabled {
		if remoteIP, ok := meta["remote_ip"].(string); ok && remoteIP != "" {
			key := normalizeIPWithOptionalPrefixes(remoteIP, f.ipv4Prefix, f.ipv6Prefix)

			var lim *rate.Limiter
			if l, ok := f.perIPLimiters.Get(key); ok {
				lim = l
			} else {
				lim = rate.NewLimiter(f.perIPRate, f.perIPBurst)
				f.perIPLimiters.Add(key, lim)
			}

			if !lim.Allow() {
				return false, errors.New("blocked: emergency per-ip limit for new pubkeys exceeded")
			}
		}
	}

	if !f.newKeyLimiter.Allow() {
		return false, errors.New("blocked: emergency global limit for new pubkeys exceeded")
	}

	f.recentSeen.Add(pk, struct{}{})
	return true, nil
}

func normalizeIPWithOptionalPrefixes(ipStr string, v4Prefix, v6Prefix int) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ipStr
	}
	if v4 := ip.To4(); v4 != nil {
		if v4Prefix > 0 {
			return (&net.IPNet{
				IP:   v4.Mask(net.CIDRMask(v4Prefix, 32)),
				Mask: net.CIDRMask(v4Prefix, 32),
			}).String()
		}
		return v4.String()
	}
	if v6Prefix > 0 {
		return (&net.IPNet{
			IP:   ip.Mask(net.CIDRMask(v6Prefix, 128)),
			Mask: net.CIDRMask(v6Prefix, 128),
		}).String()
	}
	return ip.String()
}
