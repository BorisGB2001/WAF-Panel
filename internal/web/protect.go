package web

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"wafpanel/internal/analytics"
	"wafpanel/internal/autoban"
	"wafpanel/internal/blocklist"
	"wafpanel/internal/safeline"
)

// whyNot says why ip must not be blocked on c, or "" when it may be.
// Automatic bans also skip private ranges: behind a proxy without
// X-Forwarded-For, SafeLine sees the proxy's private address for every
// visitor, and banning it would cut everyone off.
func (s *Server) whyNot(ctx context.Context, c *safeline.Client, ip string, automatic bool) string {
	p, err := prefixOf(ip)
	if err != nil {
		return "not an address"
	}
	a := p.Addr()
	for _, x := range s.protectedNets(c) {
		if p.Overlaps(x) {
			return "protected address"
		}
	}
	if automatic && (a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsUnspecified() ||
		netip.MustParsePrefix("100.64.0.0/10").Contains(a)) {
		return "private network"
	}
	if ok, err := s.allowlist(c).Covers(ctx, ip); err == nil && ok {
		return "on the allow list"
	}
	return ""
}

func prefixOf(s string) (netip.Prefix, error) {
	if a, err := netip.ParseAddr(s); err == nil {
		return netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()), nil
	}
	p, err := netip.ParsePrefix(s)
	return p.Masked(), err
}

// isPrivate reports whether an address or subnet is in a private range.
func isPrivate(ip string) bool {
	p, err := prefixOf(ip)
	return err == nil && (p.Addr().IsPrivate() || netip.MustParsePrefix("100.64.0.0/10").Contains(p.Addr()))
}

// HitOf turns a SafeLine record into what the auto-ban reads.
func HitOf(ev safeline.Event) autoban.Hit {
	return autoban.Hit{Instance: ev.Instance, IP: ev.SrcIP, Host: ev.Host, Method: ev.Method, Path: ev.URLPath,
		Denied: ev.Denied(), Type: ev.AttackType, Risk: ev.RiskLevel, EventID: ev.EventID, Time: ev.Time}
}

// goodBots are search engines the access-log rules never ban.
var goodBots = map[string]bool{"Googlebot": true, "YandexBot": true, "Bingbot": true, "Applebot": true,
	"Duckduckbot": true, "Baiduspider": true, "Petalbot": true}

// RequestOf turns an access log line into what the auto-ban reads.
func RequestOf(instance string, a analytics.Access, cl analytics.Client) autoban.Request {
	return autoban.Request{Instance: instance, Site: a.Host, IP: a.IP, Method: a.Method, Path: a.Path,
		Status: a.Status, GoodBot: goodBots[cl.Bot], Time: a.Time}
}

// StartAutoban applies the auto-ban's decisions until ctx ends.
func (s *Server) StartAutoban(ctx context.Context) {
	if s.Autoban == nil || s.Decisions == nil {
		return
	}
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case d := <-s.Decisions:
				s.applyDecision(ctx, d)
			}
		}
	}()
}

func (s *Server) applyDecision(ctx context.Context, d autoban.Decision) {
	c := s.client(d.Instance)
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	switch {
	case c == nil:
		d.Result = "skipped: unknown instance"
	case d.DryRun || s.DryRun:
		d.Result = "would block"
		if why := s.whyNot(cctx, c, d.IP, true); why != "" {
			d.Result = "skipped: " + why
		}
	default:
		if why := s.whyNot(cctx, c, d.IP, true); why != "" {
			d.Result = "skipped: " + why
			break
		}
		if ok, err := s.blocklist(c).Covers(cctx, d.IP); err == nil && ok {
			d.Result = "skipped: already blocked"
			break
		}
		meta := blocklist.Meta{By: "auto-ban", Reason: d.Reason, Source: d.Source(), Rule: d.Rule}
		if err := s.blocklist(c).BlockMany(cctx, []string{d.IP}, meta, d.Duration); err != nil {
			d.Result = "error: " + err.Error()
			s.Log.Error("auto-ban", "ip", d.IP, "err", err)
			break
		}
		d.Result = "blocked"
		term := "permanent"
		if d.Duration > 0 {
			term = d.Duration.String()
		}
		s.audit.Log("auto-ban", "", "waf.block."+d.Source(), fmt.Sprintf("%s %s for %s: %s (%s)", d.Instance, d.IP, term, d.Reason, d.Rule))
	}
	if !strings.HasPrefix(d.Result, "skipped: already") {
		s.Log.Info("auto-ban", "ip", d.IP, "kind", d.Kind, "result", d.Result, "reason", d.Reason)
	}
	if err := s.Autoban.Record(d); err != nil {
		s.Log.Error("auto-ban: saving", "err", err)
	}
}

// banMany blocks the addresses that may be blocked and returns the ones it
// skipped with the reason.
func (s *Server) banMany(ctx context.Context, c *safeline.Client, ips []string, meta blocklist.Meta, ttl time.Duration) (int, map[string]string, error) {
	skipped := map[string]string{}
	var ok []string
	for _, ip := range ips {
		if why := s.whyNot(ctx, c, ip, false); why != "" {
			skipped[ip] = why
			continue
		}
		ok = append(ok, ip)
	}
	slices.Sort(ok)
	if len(ok) == 0 {
		return 0, skipped, nil
	}
	return len(ok), skipped, s.blocklist(c).BlockMany(ctx, ok, meta, ttl)
}
