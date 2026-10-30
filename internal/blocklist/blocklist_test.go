package blocklist

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"

	"wafpanel/internal/safeline"
)

// fakeAPI keeps groups and policies in memory like SafeLine does.
type fakeAPI struct {
	groups   []safeline.IPGroup
	policies []safeline.Policy
	writes   int
}

func (f *fakeAPI) IPGroups(context.Context) ([]safeline.IPGroup, error) { return f.groups, nil }
func (f *fakeAPI) IPGroup(_ context.Context, id int) (safeline.IPGroup, error) {
	for _, g := range f.groups {
		if g.ID == id {
			g.IPs = slices.Clone(g.IPs)
			return g, nil
		}
	}
	return safeline.IPGroup{}, nil
}
func (f *fakeAPI) CreateIPGroup(_ context.Context, comment string, ips []string) error {
	f.writes++
	f.groups = append(f.groups, safeline.IPGroup{ID: len(f.groups) + 10, Comment: comment, IPs: ips})
	return nil
}
func (f *fakeAPI) UpdateIPGroup(_ context.Context, g safeline.IPGroup) error {
	f.writes++
	for i := range f.groups {
		if f.groups[i].ID == g.ID {
			f.groups[i].IPs = g.IPs
		}
	}
	return nil
}
func (f *fakeAPI) AppendIPGroup(_ context.Context, id int, ips []string) error {
	f.writes++
	for i := range f.groups {
		if f.groups[i].ID == id {
			f.groups[i].IPs = append(f.groups[i].IPs, ips...)
		}
	}
	return nil
}
func (f *fakeAPI) Policies(context.Context) ([]safeline.Policy, error) { return f.policies, nil }
func (f *fakeAPI) CreateDenyGroupPolicy(_ context.Context, name string, gid int) error {
	f.writes++
	f.policies = append(f.policies, safeline.Policy{ID: 99, Name: name, Action: 1, IsEnabled: true,
		Pattern: [][]safeline.PolicyPattern{{{K: "src_ip", Op: "in", V: []string{itoa(gid)}}}}})
	return nil
}
func (f *fakeAPI) SetPolicyEnabled(_ context.Context, id int, on bool) error {
	f.writes++
	f.policies[0].IsEnabled = on
	return nil
}

func itoa(i int) string { return strconv.Itoa(i) }

func newManager(t *testing.T, api API) *Manager {
	return &Manager{Instance: "prod", API: api, File: filepath.Join(t.TempDir(), "bl.json"),
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Protected: []netip.Prefix{netip.MustParsePrefix("192.0.2.10/32")}}
}

func TestNormalize(t *testing.T) {
	m := newManager(t, &fakeAPI{})
	for in, want := range map[string]string{"203.0.113.5": "203.0.113.5", "203.0.113.7/24": "203.0.113.0/24", "::ffff:203.0.113.9": "203.0.113.9", "2001:db8::1": "2001:db8::1"} {
		if got, err := m.Normalize(in, "198.51.100.200"); err != nil || got != want {
			t.Errorf("Normalize(%q) = %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"0.0.0.0/0", "10.0.0.0/8", "127.0.0.1", "nonsense", "192.0.2.0/24", "198.51.100.0/24", "2001:db8::/32"} {
		if _, err := m.Normalize(bad, "198.51.100.200"); err == nil {
			t.Errorf("Normalize(%q) accepted", bad)
		}
	}
}

func TestBlockUnblockExpire(t *testing.T) {
	api := &fakeAPI{}
	m := newManager(t, api)
	ctx := context.Background()

	st, err := m.Status(ctx)
	if err != nil || st.GroupID != 0 || api.writes != 0 {
		t.Fatalf("status must not create anything: %+v %v writes=%d", st, err, api.writes)
	}
	if err := m.Block(ctx, "203.0.113.5", "scanner", "admin", time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := m.Block(ctx, "198.51.100.0/24", "botnet", "admin", 0); err != nil {
		t.Fatal(err)
	}
	st, _ = m.Status(ctx)
	if st.PolicyID != 99 || !st.PolicyEnabled || len(st.Entries) != 2 {
		t.Fatalf("status %+v", st)
	}
	if len(api.groups) != 1 || len(api.policies) != 1 {
		t.Fatal("group or policy created twice")
	}

	// An address added in the console shows up as external.
	api.groups[0].IPs = append(api.groups[0].IPs, "192.0.2.10")
	st, _ = m.Status(ctx)
	ext := 0
	for _, e := range st.Entries {
		if e.External {
			ext++
		}
	}
	if ext != 1 {
		t.Fatalf("external entries: %d", ext)
	}

	if got := m.Expired(time.Now().Add(2 * time.Hour)); !slices.Equal(got, []string{"203.0.113.5"}) {
		t.Fatalf("expired: %v", got)
	}
	if err := m.Unblock(ctx, "203.0.113.5"); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(api.groups[0].IPs, "203.0.113.5") {
		t.Fatal("not removed from the group")
	}
	// Removing the last real address keeps the group valid.
	m.Unblock(ctx, "198.51.100.0/24")
	m.Unblock(ctx, "192.0.2.10")
	if !slices.Equal(api.groups[0].IPs, []string{placeholder}) {
		t.Fatalf("group after removing all: %v", api.groups[0].IPs)
	}
}
