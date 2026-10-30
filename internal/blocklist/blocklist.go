// Package blocklist blocks source IPs on a SafeLine instance through one IP
// group and one deny rule that the panel owns. SafeLine keeps the list
// itself; the panel keeps who blocked what, why and until when.
package blocklist

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"slices"
	"sync"
	"time"
	"wafpanel/internal/i18n"

	"wafpanel/internal/auth"
	"wafpanel/internal/safeline"
)

const (
	// GroupComment and PolicyName identify the objects the panel owns.
	GroupComment = "WAF Panel blocklist"
	PolicyName   = "WAF Panel: IP blocklist"
)

// API is the part of safeline.Client the manager needs.
type API interface {
	IPGroups(ctx context.Context) ([]safeline.IPGroup, error)
	IPGroup(ctx context.Context, id int) (safeline.IPGroup, error)
	CreateIPGroup(ctx context.Context, comment string, ips []string) error
	UpdateIPGroup(ctx context.Context, g safeline.IPGroup) error
	AppendIPGroup(ctx context.Context, id int, ips []string) error
	Policies(ctx context.Context) ([]safeline.Policy, error)
	CreateDenyGroupPolicy(ctx context.Context, name string, groupID int) error
	SetPolicyEnabled(ctx context.Context, id int, enabled bool) error
}

type Meta struct {
	By      string    `json:"by"`
	Reason  string    `json:"reason"`
	At      time.Time `json:"at"`
	Expires time.Time `json:"expires,omitempty"`
}

// Entry is one blocked address as shown in the panel.
type Entry struct {
	IP string
	Meta
	// External is set for addresses added in the SafeLine console.
	External bool
}

type Status struct {
	GroupID       int
	PolicyID      int
	PolicyEnabled bool
	Entries       []Entry
}

type Manager struct {
	Instance string
	API      API
	File     string // metadata, JSON
	Log      *slog.Logger
	// Protected addresses can never be blocked (the WAF host itself, ...).
	Protected []netip.Prefix

	mu   sync.Mutex
	meta map[string]Meta
}

func (m *Manager) load() {
	if m.meta != nil {
		return
	}
	m.meta = map[string]Meta{}
	if b, err := os.ReadFile(m.File); err == nil {
		json.Unmarshal(b, &m.meta)
	}
}

func (m *Manager) save() error {
	b, err := json.MarshalIndent(m.meta, "", "  ")
	if err != nil {
		return err
	}
	return auth.WriteFileAtomic(m.File, b, 0o600)
}

// Normalize parses an IP or CIDR and refuses ranges that are too broad.
func (m *Manager) Normalize(s string, requester string) (string, error) {
	var p netip.Prefix
	if a, err := netip.ParseAddr(s); err == nil {
		p = netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen())
	} else if p, err = netip.ParsePrefix(s); err != nil {
		return "", i18n.Errorf("%q is neither an IP address nor a subnet", s)
	}
	p = p.Masked()
	a := p.Addr()
	switch {
	case a.Is4() && p.Bits() < 16, a.Is6() && p.Bits() < 48:
		return "", i18n.Errorf("The subnet is too wide: at most /16 for IPv4 and /48 for IPv6")
	case a.IsLoopback(), a.IsUnspecified(), a.IsMulticast():
		return "", i18n.Errorf("This address cannot be blocked")
	}
	if r, err := netip.ParseAddr(requester); err == nil && p.Contains(r.Unmap()) {
		return "", i18n.Errorf("The subnet contains your own address — you would lose access")
	}
	for _, x := range m.Protected {
		if p.Overlaps(x) {
			return "", i18n.Errorf("The subnet overlaps the protected address %s", x)
		}
	}
	if p.IsSingleIP() {
		return a.String(), nil
	}
	return p.String(), nil
}

// ensure finds or creates the group and the deny rule.
func (m *Manager) ensure(ctx context.Context, create bool) (group safeline.IPGroup, policy *safeline.Policy, err error) {
	find := func() (int, error) {
		gs, err := m.API.IPGroups(ctx)
		if err != nil {
			return 0, err
		}
		for _, g := range gs {
			if g.Comment == GroupComment && !g.Builtin {
				return g.ID, nil
			}
		}
		return 0, nil
	}
	id, err := find()
	if err != nil {
		return group, nil, err
	}
	if id == 0 {
		if !create {
			return group, nil, nil
		}
		// SafeLine wants a non-empty list; a TEST-NET address keeps it valid.
		if err := m.API.CreateIPGroup(ctx, GroupComment, []string{placeholder}); err != nil {
			return group, nil, err
		}
		if id, err = find(); err != nil || id == 0 {
			return group, nil, fmt.Errorf("the group did not appear after creation: %v", err)
		}
		m.Log.Info("blocklist group created", "instance", m.Instance, "id", id)
	}
	if group, err = m.API.IPGroup(ctx, id); err != nil {
		return group, nil, err
	}
	findPolicy := func() (*safeline.Policy, error) {
		ps, err := m.API.Policies(ctx)
		if err != nil {
			return nil, err
		}
		for i, p := range ps {
			if p.Builtin || p.Action != 1 || len(p.Pattern) != 1 || len(p.Pattern[0]) != 1 {
				continue
			}
			c := p.Pattern[0][0]
			if c.K == "src_ip" && c.Op == "in" && slices.Equal(c.V, []string{fmt.Sprint(id)}) {
				return &ps[i], nil
			}
		}
		return nil, nil
	}
	if policy, err = findPolicy(); err != nil {
		return group, nil, err
	}
	if policy == nil && create {
		if err := m.API.CreateDenyGroupPolicy(ctx, PolicyName, id); err != nil {
			return group, nil, err
		}
		if policy, err = findPolicy(); err != nil || policy == nil {
			return group, nil, fmt.Errorf("the rule did not appear after creation: %v", err)
		}
		m.Log.Info("blocklist policy created", "instance", m.Instance, "id", policy.ID)
	}
	if policy != nil && !policy.IsEnabled && create {
		if err := m.API.SetPolicyEnabled(ctx, policy.ID, true); err != nil {
			return group, nil, err
		}
		policy.IsEnabled = true
	}
	return group, policy, nil
}

const placeholder = "192.0.2.255"

func (m *Manager) Status(ctx context.Context) (Status, error) {
	g, p, err := m.ensure(ctx, false)
	if err != nil {
		return Status{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.load()
	st := Status{GroupID: g.ID}
	if p != nil {
		st.PolicyID, st.PolicyEnabled = p.ID, p.IsEnabled
	}
	for _, ip := range g.IPs {
		if ip == placeholder {
			continue
		}
		e := Entry{IP: ip}
		if meta, ok := m.meta[ip]; ok {
			e.Meta = meta
		} else {
			e.External = true
		}
		st.Entries = append(st.Entries, e)
	}
	slices.SortFunc(st.Entries, func(a, b Entry) int { return b.At.Compare(a.At) })
	return st, nil
}

// Block adds an address; ttl 0 means until unblocked by hand.
func (m *Manager) Block(ctx context.Context, ip, reason, by string, ttl time.Duration) error {
	g, _, err := m.ensure(ctx, true)
	if err != nil {
		return err
	}
	if !slices.Contains(g.IPs, ip) {
		if err := m.API.AppendIPGroup(ctx, g.ID, []string{ip}); err != nil {
			return err
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.load()
	meta := Meta{By: by, Reason: reason, At: time.Now()}
	if ttl > 0 {
		meta.Expires = meta.At.Add(ttl)
	}
	m.meta[ip] = meta
	return m.save()
}

func (m *Manager) Unblock(ctx context.Context, ip string) error {
	g, _, err := m.ensure(ctx, false)
	if err != nil {
		return err
	}
	if g.ID != 0 && slices.Contains(g.IPs, ip) {
		g.IPs = slices.DeleteFunc(slices.Clone(g.IPs), func(x string) bool { return x == ip })
		if len(g.IPs) == 0 {
			g.IPs = []string{placeholder}
		}
		if err := m.API.UpdateIPGroup(ctx, g); err != nil {
			return err
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.load()
	delete(m.meta, ip)
	return m.save()
}

// Expired returns addresses whose block time is over.
func (m *Manager) Expired(now time.Time) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.load()
	var out []string
	for ip, meta := range m.meta {
		if !meta.Expires.IsZero() && now.After(meta.Expires) {
			out = append(out, ip)
		}
	}
	slices.Sort(out)
	return out
}

// RunExpiry unblocks expired addresses every minute until ctx ends;
// onUnblock is called for every address it removed (for the audit log).
func (m *Manager) RunExpiry(ctx context.Context, onUnblock func(ip string, err error)) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		for _, ip := range m.Expired(time.Now()) {
			cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			err := m.Unblock(cctx, ip)
			cancel()
			onUnblock(ip, err)
		}
	}
}
