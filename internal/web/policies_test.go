package web

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"wafpanel/internal/safeline"
)

// policyFake keeps rules the way SafeLine does.
type policyFake struct {
	mu       sync.Mutex
	policies []map[string]any
	next     int
	calls    []string
	bodies   []map[string]any
}

func newPolicyFake() *policyFake {
	return &policyFake{next: 20, policies: []map[string]any{
		{"id": 1.0, "name": "Malicious IP", "action": 1.0, "is_enabled": true, "builtin": true,
			"pattern": []any{[]any{map[string]any{"k": "src_ip", "op": "in", "v": []any{"1"}, "sub_k": ""}}}},
		{"id": 8.0, "name": "Office", "action": 0.0, "order": 1.0, "is_enabled": true, "log": true, "req_count": 1234.0, "creator": "admin",
			"pattern": []any{[]any{map[string]any{"k": "src_ip", "op": "cidr", "v": []any{"198.51.100.0/24"}, "sub_k": ""}}}},
		{"id": 9.0, "name": "Geo", "action": 1.0, "order": 1.0, "is_enabled": false,
			"pattern": []any{[]any{map[string]any{"k": "src_ip", "op": "geo_eq", "v": []any{"CN"}, "sub_k": ""}}}},
		{"id": 10.0, "name": "Scrapers", "action": 1.0, "order": 1.0, "is_enabled": true,
			"pattern": []any{[]any{map[string]any{"k": "uri", "op": "prefix", "v": []any{"/export"}, "sub_k": ""}}}},
	}}
}

func (f *policyFake) find(id float64) int {
	for i, p := range f.policies {
		if p["id"] == id {
			return i
		}
	}
	return -1
}

func (f *policyFake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	ok := func(data any) { json.NewEncoder(w).Encode(map[string]any{"err": nil, "msg": "", "data": data}) }
	var body map[string]any
	if r.Method != http.MethodGet {
		json.NewDecoder(r.Body).Decode(&body)
		f.calls = append(f.calls, r.Method+" "+r.URL.Path)
		f.bodies = append(f.bodies, body)
	}
	switch r.Method + " " + r.URL.Path {
	case "GET /api/open/policy":
		ok(map[string]any{"total": len(f.policies), "data": f.policies})
	case "POST /api/open/policy":
		body["id"] = float64(f.next)
		f.next++
		if body["insert_position"] == "first" {
			f.policies = append([]map[string]any{body}, f.policies...)
		} else {
			f.policies = append(f.policies, body)
		}
		ok(nil)
	case "PUT /api/open/policy":
		f.policies[f.find(body["id"].(float64))] = body
		ok(nil)
	case "DELETE /api/open/policy":
		i := f.find(body["id"].(float64))
		f.policies = append(f.policies[:i], f.policies[i+1:]...)
		ok(nil)
	case "PUT /api/open/policy/switch":
		f.policies[f.find(body["id"].(float64))]["is_enabled"] = body["is_enabled"]
		ok(nil)
	case "PUT /api/open/policy/orders":
		for _, o := range body["orders"].([]any) {
			o := o.(map[string]any)
			f.policies[f.find(o["id"].(float64))]["order"] = o["order"]
		}
		ok(nil)
	case "GET /api/open/ipgroup":
		ok(map[string]any{"total": 2, "nodes": []safeline.IPGroup{{ID: 1, Comment: "Malicious IPs", Builtin: true}, {ID: 5, Comment: "Scanners"}}})
	case "GET /api/open/site":
		ok(map[string]any{"data": []map[string]any{{"id": 4, "server_names": []string{"im.example.ru"}, "is_enabled": true, "mode": 2, "comment": "mattermost"}}})
	default:
		readOnlySafeLine().ServeHTTP(w, r)
	}
}

func TestPolicies(t *testing.T) {
	fake := newPolicyFake()
	ts, s, _ := newTestServerWith(t, fake)
	c := browser(ts)
	pw, _ := os.ReadFile(filepath.Join(s.Cfg.Web.DataDir, "initial-admin-password"))
	login(t, ts, c, "admin", strings.TrimSpace(string(pw)))

	code, page := get(t, ts, c, "/policies")
	if code != 200 || !strings.Contains(page, "Office") || !strings.Contains(page, "198.51.100.0/24") || !strings.Contains(page, "Malicious IPs") {
		t.Fatalf("policies page %d %s", code, page)
	}
	if strings.Contains(page, "/policies/prod/1/edit") || strings.Contains(page, "/policies/prod/9/edit") || !strings.Contains(page, "/policies/prod/8/edit") {
		t.Fatal("only rules the editor can represent get an Edit link")
	}
	// Allow and deny keep separate orders: Office (allow, 1) is no tie with
	// the deny rules, while Geo and Scrapers (deny, 1) are.
	if strings.Count(page, "Another rule has the same position") != 2 {
		t.Error("Geo and Scrapers share deny order 1 and must both be marked")
	}
	if len(fake.calls) != 0 {
		t.Fatalf("viewing wrote: %v", fake.calls)
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
	// rows are g, k, sub, op, v
	form := func(action string, rows ...[5]string) url.Values {
		v := url.Values{"instance": {"prod"}, "name": {"Admin area"}, "action": {action}, "enabled": {"on"},
			"position": {"first"}, "reason": {"test"}}
		for _, r := range rows {
			v.Add("g", r[0])
			v.Add("k", r[1])
			v.Add("sub", r[2])
			v.Add("op", r[3])
			v.Add("v", r[4])
		}
		return v
	}

	// Rejected before anything reaches SafeLine.
	for name, v := range map[string]url.Values{
		"bad ip":          form("1", [5]string{"0", "src_ip", "", "eq", "1.2.3"}),
		"bad subnet":      form("1", [5]string{"0", "src_ip", "", "cidr", "10.0.0.0/33"}),
		"unknown group":   form("1", [5]string{"0", "src_ip", "", "in", "Nobody"}),
		"bad regex":       form("1", [5]string{"0", "uri", "", "re", "(unclosed"}),
		"no header name":  form("1", [5]string{"0", "req_header", "", "exist", ""}),
		"wrong operator":  form("1", [5]string{"0", "method", "", "prefix", "GET"}),
		"geo operator":    form("1", [5]string{"0", "src_ip", "", "geo_eq", "CN"}),
		"no conditions":   form("1"),
		"no values":       form("1", [5]string{"0", "uri", "", "prefix", ""}),
		"blocks yourself": form("1", [5]string{"0", "src_ip", "", "cidr", "127.0.0.0/8"}),
		"unknown site":    form("1", [5]string{"0", "website", "", "eq", "nope.example.ru"}),
	} {
		if code, _ := post("/policies", v); code != http.StatusBadRequest {
			t.Errorf("%s: %d", name, code)
		}
	}
	noReason := form("1", [5]string{"0", "uri", "", "prefix", "/admin"})
	noReason.Del("reason")
	if code, _ := post("/policies", noReason); code != http.StatusBadRequest {
		t.Errorf("no reason: %d", code)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("rejected forms wrote: %v", fake.calls)
	}

	// (scanners AND /admin) OR (X-Debug header exists on im.example.ru), record only.
	v := form("1",
		[5]string{"0", "src_ip", "", "in", "scanners"},
		[5]string{"0", "uri", "", "prefix", "/admin\n/admin"},
		[5]string{"3", "req_header", "X-Debug", "exist", "ignored"},
		[5]string{"3", "website", "", "eq", "IM.example.ru"},
		[5]string{"3", "", "", "eq", ""}, // an empty row from the editor
	)
	v.Set("monitor", "on")
	v.Set("log", "on")
	if code, page := post("/policies", v); code != http.StatusSeeOther {
		t.Fatalf("create: %d %s", code, page)
	}
	b := fake.bodies[0]
	if b["insert_position"] != "first" || b["action"] != 1.0 || b["monitor"] != true || b["log"] != false {
		t.Fatalf("create body %+v", b)
	}
	pj, _ := json.Marshal(b["pattern"])
	if want := `[[{"k":"src_ip","op":"in","sub_k":"","v":["5"]},{"k":"uri","op":"prefix","sub_k":"","v":["/admin"]}],[{"k":"req_header","op":"exist","sub_k":"X-Debug","v":[]},{"k":"website","op":"eq","sub_k":"","v":["4"]}]]`; string(pj) != want {
		t.Fatalf("pattern\n got %s\nwant %s", pj, want)
	}

	// The editor shows names, not ids, and an update keeps the place.
	if code, page := get(t, ts, c, "/policies/prod/20/edit"); code != 200 || !strings.Contains(page, ">Scanners<") && !strings.Contains(page, "Scanners</textarea>") || !strings.Contains(page, "im.example.ru</textarea>") {
		t.Fatalf("edit form %d", code)
	}
	v = form("0", [5]string{"0", "src_ip", "", "eq", "203.0.113.9"})
	v.Set("position", "")
	v.Set("log", "on")
	if code, _ := post("/policies/prod/20", v); code != http.StatusSeeOther {
		t.Fatalf("update: %d", code)
	}
	if b := fake.bodies[1]; b["id"] != 20.0 || b["action"] != 0.0 || b["log"] != true || b["monitor"] != false {
		t.Fatalf("update body %+v", b)
	} else if _, has := b["insert_position"]; has {
		t.Fatal("keeping the place must not send insert_position")
	}

	// Built-in and geo rules are not edited in the panel.
	resp, _ := c.Get(ts.URL + "/policies/prod/1/edit")
	body(t, resp)
	if loc := resp.Header.Get("Location"); resp.StatusCode != http.StatusSeeOther || !strings.Contains(loc, "err=") {
		t.Fatalf("built-in edit not refused: %s", loc)
	}
	if code, _ := post("/policies/prod/9", form("1", [5]string{"0", "uri", "", "prefix", "/x"})); code != http.StatusBadRequest {
		t.Fatalf("geo rule overwritten: %d", code)
	}

	// Switching needs a reason; deleting needs the name; built-in stays.
	n := len(fake.calls)
	post("/policies/prod/8/enabled", url.Values{"enabled": {"0"}})
	post("/policies/prod/1/delete", url.Values{"reason": {"x"}, "confirm": {"Malicious IP"}})
	post("/policies/prod/8/delete", url.Values{"reason": {"x"}, "confirm": {"office"}})
	if len(fake.calls) != n {
		t.Fatalf("refused actions wrote: %v", fake.calls[n:])
	}
	post("/policies/prod/1/enabled", url.Values{"enabled": {"0"}, "reason": {"false positives"}})
	post("/policies/prod/8/delete", url.Values{"reason": {"office moved"}, "confirm": {"Office"}})
	if fake.find(8) >= 0 || fake.policies[fake.find(1)]["is_enabled"] != false {
		t.Fatalf("state after switch and delete: %v", fake.policies)
	}
	_, page = get(t, ts, c, "/audit")
	for _, a := range []string{"policy.create", "policy.update", "policy.enabled", "policy.delete"} {
		if !strings.Contains(page, a) {
			t.Errorf("audit lacks %s", a)
		}
	}
}

func TestPolicyOrder(t *testing.T) {
	fake := newPolicyFake()
	fake.policies = append(fake.policies, map[string]any{"id": 11.0, "name": "Bots", "action": 1.0, "order": 2.0, "is_enabled": true,
		"pattern": []any{[]any{map[string]any{"k": "method", "op": "eq", "v": []any{"TRACE"}, "sub_k": ""}}}})
	ts, s, _ := newTestServerWith(t, fake)
	c := browser(ts)
	pw, _ := os.ReadFile(filepath.Join(s.Cfg.Web.DataDir, "initial-admin-password"))
	login(t, ts, c, "admin", strings.TrimSpace(string(pw)))
	_, page := get(t, ts, c, "/policies")
	csrf := csrfRe.FindStringSubmatch(page)[1]
	post := func(v url.Values) {
		v.Set("csrf", csrf)
		v.Set("action", "1")
		resp, err := c.PostForm(ts.URL+"/policies/prod/order", v)
		if err != nil {
			t.Fatal(err)
		}
		body(t, resp)
	}
	orders := func() map[string]float64 {
		m := map[string]float64{}
		for _, p := range fake.policies {
			if o, ok := p["order"].(float64); ok {
				m[p["name"].(string)] = o
			}
		}
		return m
	}

	post(url.Values{"o11": {"1"}})
	if len(fake.calls) != 0 {
		t.Fatal("reordered without a reason")
	}
	// Bots moves onto position 1 and goes before the rules there; the tie
	// between Geo and Scrapers is resolved in their listed order; the allow
	// list is not touched.
	post(url.Values{"o9": {"1"}, "o10": {"2"}, "o11": {"1"}, "reason": {"bots first"}})
	if got := orders(); got["Bots"] != 1 || got["Geo"] != 2 || got["Scrapers"] != 3 || got["Office"] != 1 {
		t.Fatalf("orders %v", got)
	}
	if n := len(fake.bodies[0]["orders"].([]any)); n != 3 {
		t.Fatalf("sent %d orders, want the deny list only", n)
	}
	// Nothing to do once the list is numbered 1..n.
	post(url.Values{"o11": {"1"}, "o9": {"2"}, "o10": {"3"}, "reason": {"again"}})
	if len(fake.calls) != 1 {
		t.Fatalf("unchanged order sent again: %v", fake.calls)
	}
	// Moving down past the end lands at the bottom.
	post(url.Values{"o11": {"9"}, "reason": {"bots last"}})
	if got := orders(); got["Geo"] != 1 || got["Scrapers"] != 2 || got["Bots"] != 3 {
		t.Fatalf("orders %v", got)
	}
}

func TestBlocksAddress(t *testing.T) {
	p := func(op string, v ...string) safeline.PolicyPattern {
		return safeline.PolicyPattern{K: "src_ip", Op: op, V: v}
	}
	deny := func(and ...safeline.PolicyPattern) safeline.PolicySpec {
		return safeline.PolicySpec{Action: 1, Enabled: true, Pattern: [][]safeline.PolicyPattern{and}}
	}
	for _, c := range []struct {
		s    safeline.PolicySpec
		want bool
	}{
		{deny(p("eq", "192.0.2.7")), true},
		{deny(p("cidr", "192.0.2.0/24")), true},
		{deny(p("match", "192.0.2.*")), true},
		{deny(p("not_cidr", "10.0.0.0/8")), true},
		{deny(p("not_eq", "192.0.2.7")), false},
		{deny(p("cidr", "192.0.2.0/24"), safeline.PolicyPattern{K: "uri", Op: "prefix", V: []string{"/admin"}}), false},
		{deny(p("in", "5")), false},
		{safeline.PolicySpec{Action: 1, Enabled: true, Monitor: true, Pattern: [][]safeline.PolicyPattern{{p("eq", "192.0.2.7")}}}, false},
		{safeline.PolicySpec{Action: 0, Enabled: true, Pattern: [][]safeline.PolicyPattern{{p("eq", "192.0.2.7")}}}, false},
	} {
		if got := blocksAddress(c.s, "192.0.2.7"); got != c.want {
			t.Errorf("%+v: %v", c.s.Pattern, got)
		}
	}
}
