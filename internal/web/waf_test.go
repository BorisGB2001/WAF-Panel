package web

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"wafpanel/internal/safeline"
)

// statefulSafeLine serves the write API on top of the read-only fake.
type statefulSafeLine struct {
	mu       sync.Mutex
	groups   []safeline.IPGroup
	policies []safeline.Policy
	mode     int
	calls    []string
}

func (f *statefulSafeLine) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	ok := func(data any) {
		json.NewEncoder(w).Encode(map[string]any{"err": nil, "msg": "", "data": data})
	}
	var body map[string]any
	if r.Method != http.MethodGet {
		json.NewDecoder(r.Body).Decode(&body)
		f.calls = append(f.calls, r.Method+" "+r.URL.Path)
	}
	switch r.Method + " " + r.URL.Path {
	case "GET /api/open/site":
		ok(map[string]any{"data": []map[string]any{{"id": 4, "server_names": []string{"im.example.ru"}, "is_enabled": true, "mode": f.mode, "title": "IM"}}})
	case "PUT /api/open/site/mode":
		f.mode = int(body["mode"].(float64))
		ok(nil)
	case "GET /api/open/ipgroup":
		ok(map[string]any{"total": len(f.groups), "nodes": f.groups})
	case "GET /api/open/ipgroup/detail":
		for _, g := range f.groups {
			if r.URL.Query().Get("id") == itoa(int64(g.ID)) {
				ok(map[string]any{"data": g})
				return
			}
		}
		ok(map[string]any{"data": nil})
	case "POST /api/open/ipgroup":
		var ips []string
		for _, x := range body["ips"].([]any) {
			ips = append(ips, x.(string))
		}
		f.groups = append(f.groups, safeline.IPGroup{ID: 10 + len(f.groups), Comment: body["comment"].(string), IPs: ips})
		ok(nil)
	case "POST /api/open/ipgroup/append":
		g := f.group(body["ip_group_ids"].([]any)[0])
		for _, x := range body["ips"].([]any) {
			g.IPs = append(g.IPs, x.(string))
		}
		ok(nil)
	case "PUT /api/open/ipgroup":
		var ips []string
		for _, x := range body["ips"].([]any) {
			ips = append(ips, x.(string))
		}
		f.group(body["id"]).IPs = ips
		ok(nil)
	case "GET /api/open/policy":
		ok(map[string]any{"total": len(f.policies), "data": f.policies})
	case "POST /api/open/policy":
		b, _ := json.Marshal(body["pattern"])
		var p [][]safeline.PolicyPattern
		json.Unmarshal(b, &p)
		f.policies = append(f.policies, safeline.Policy{ID: 7 + len(f.policies), Name: body["name"].(string), Action: int(body["action"].(float64)),
			IsEnabled: body["is_enabled"].(bool), Monitor: body["monitor"] == true, Pattern: p})
		ok(nil)
	case "PUT /api/open/policy":
		for i := range f.policies {
			if float64(f.policies[i].ID) == body["id"] {
				f.policies[i].IsEnabled, f.policies[i].Monitor = body["is_enabled"].(bool), body["monitor"] == true
			}
		}
		ok(nil)
	case "DELETE /api/open/policy":
		f.policies = slices.DeleteFunc(f.policies, func(p safeline.Policy) bool { return float64(p.ID) == body["id"] })
		ok(nil)
	default:
		readOnlySafeLine().ServeHTTP(w, r)
	}
}

// group finds a group by the id of a request body; the first one when the
// body has none.
func (f *statefulSafeLine) group(id any) *safeline.IPGroup {
	for i := range f.groups {
		if float64(f.groups[i].ID) == id {
			return &f.groups[i]
		}
	}
	return &f.groups[0]
}

func TestWAFManagement(t *testing.T) {
	fake := &statefulSafeLine{mode: 2}
	ts, s, _ := newTestServerWith(t, fake)
	c := browser(ts)
	pw, _ := os.ReadFile(filepath.Join(s.Cfg.Web.DataDir, "initial-admin-password"))
	login(t, ts, c, "admin", strings.TrimSpace(string(pw)))

	code, page := get(t, ts, c, "/waf?block=198.51.100.7")
	if code != 200 || !strings.Contains(page, "in Monitoring mode") || !strings.Contains(page, `value="198.51.100.7"`) {
		t.Fatalf("waf page: %d", code)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("viewing the page wrote to SafeLine: %v", fake.calls)
	}
	csrf := csrfRe.FindStringSubmatch(page)[1]
	post := func(path string, v url.Values) (int, string) {
		v.Set("csrf", csrf)
		resp, err := c.PostForm(ts.URL+path, v)
		if err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode, body(t, resp)
	}

	// Safety checks happen before any write.
	for _, bad := range []url.Values{
		{"ip": {"10.0.0.0/8"}, "reason": {"x"}, "ttl": {"24h"}},
		{"ip": {"198.51.100.7"}, "reason": {""}, "ttl": {"24h"}},
		{"ip": {"127.0.0.1"}, "reason": {"x"}, "ttl": {"24h"}}, // the test client itself
	} {
		if code, _ := post("/waf/prod/block", bad); code != http.StatusBadRequest {
			t.Errorf("block %v: %d", bad, code)
		}
	}
	if len(fake.calls) != 0 {
		t.Fatalf("rejected blocks wrote to SafeLine: %v", fake.calls)
	}

	if code, _ := post("/waf/prod/block", url.Values{"ip": {"198.51.100.7"}, "reason": {"scanner"}, "ttl": {"1h"}}); code != http.StatusSeeOther {
		t.Fatalf("block: %d", code)
	}
	if len(fake.groups) != 1 || !slices.Contains(fake.groups[0].IPs, "198.51.100.7") || len(fake.policies) != 1 {
		t.Fatalf("SafeLine state after block: %+v %+v", fake.groups, fake.policies)
	}
	if p := fake.policies[0]; p.Pattern[0][0].K != "src_ip" || p.Pattern[0][0].V[0] != "10" {
		t.Fatalf("deny rule does not reference the group: %+v", p)
	}
	// The redirect keeps the instance and shows the message once.
	resp, _ := c.PostForm(ts.URL+"/waf/prod/block", url.Values{"csrf": {csrf}, "ip": {"198.51.100.8"}, "reason": {"scanner"}, "ttl": {"1h"}})
	body(t, resp)
	if loc := resp.Header.Get("Location"); strings.Count(loc, "?") != 1 || !strings.Contains(loc, "&ok=") {
		t.Fatalf("redirect %q", loc)
	}
	_, page = get(t, ts, c, resp.Header.Get("Location"))
	if !strings.Contains(page, "Blocked 198.51.100.8") {
		t.Fatal("flash message not shown after block")
	}
	post("/waf/prod/unblock", url.Values{"ip": {"198.51.100.8"}})
	_, page = get(t, ts, c, "/waf")
	if !strings.Contains(page, "scanner") || !strings.Contains(page, "rule #7 enabled") {
		t.Fatal("blocked entry not shown")
	}
	if code, _ := post("/waf/prod/unblock", url.Values{"ip": {"198.51.100.7"}}); code != http.StatusSeeOther || slices.Contains(fake.groups[0].IPs, "198.51.100.7") {
		t.Fatalf("unblock: %d %v", code, fake.groups[0].IPs)
	}

	// Site mode needs a reason and the site name typed in.
	if code, _ := post("/waf/prod/sites/4/mode", url.Values{"mode": {"0"}, "reason": {"go"}, "confirm": {"wrong"}}); code != http.StatusBadRequest || fake.mode != 2 {
		t.Fatalf("mode without confirmation: %d mode=%d", code, fake.mode)
	}
	if code, _ := post("/waf/prod/sites/4/mode", url.Values{"mode": {"0"}, "reason": {"go"}, "confirm": {"im.example.ru"}}); code != http.StatusSeeOther || fake.mode != 0 {
		t.Fatalf("mode change: %d mode=%d", code, fake.mode)
	}
	_, audit := get(t, ts, c, "/audit")
	for _, want := range []string{"waf.block", "waf.unblock", "waf.site_mode"} {
		if !strings.Contains(audit, want) {
			t.Errorf("audit has no %s", want)
		}
	}

	// A viewer sees the page but cannot act.
	post("/users", url.Values{"name": {"v2"}, "role": {"viewer"}, "password": {"viewer-password-2"}})
	v := browser(ts)
	login(t, ts, v, "v2", "viewer-password-2")
	_, vp := get(t, ts, v, "/waf")
	if strings.Contains(vp, "Block</button>") {
		t.Fatal("viewer sees the block form")
	}
	vcsrf := csrfRe.FindStringSubmatch(vp)[1]
	resp, _ = v.PostForm(ts.URL+"/waf/prod/block", url.Values{"csrf": {vcsrf}, "ip": {"198.51.100.9"}, "reason": {"x"}, "ttl": {"1h"}})
	if body(t, resp); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer blocked an IP: %d", resp.StatusCode)
	}
}
