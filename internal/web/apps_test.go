package web

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// siteFake keeps sites and certificates like SafeLine does.
type siteFake struct {
	mu    sync.Mutex
	sites map[int]map[string]any
	certs []map[string]any
	next  int
	calls []string
}

func newSiteFake() *siteFake {
	return &siteFake{next: 10, sites: map[int]map[string]any{4: {
		"id": 4.0, "title": "IM", "comment": "mattermost", "server_names": []any{"im.example.ru"}, "ports": []any{"443_ssl"},
		"upstreams": []any{"https://10.0.0.12:443"}, "is_enabled": true, "mode": 2.0, "type": 0.0, "cert_id": 1.0,
		"health_check": true, "forbidden_html_path": "/custom/403.html",
		"load_balance": map[string]any{"balance_type": 1.0, "upstreams": []any{map[string]any{"address": "https://10.0.0.12:443", "weight": 5.0, "role": "primary"}}},
		"health_state": map[string]any{"https://10.0.0.12:443": map[string]any{"state": 2.0, "error": ""}},
	}}, certs: []map[string]any{{"id": 1, "type": 2, "domains": []string{"*.example.ru"}, "issuer": "Test CA",
		"related_sites": []string{"im.example.ru"}, "valid_before": time.Now().Add(400 * 24 * time.Hour).Format(time.RFC3339)}}}
}

func (f *siteFake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	ok := func(data any) { json.NewEncoder(w).Encode(map[string]any{"err": nil, "msg": "", "data": data}) }
	var body map[string]any
	if r.Method != http.MethodGet {
		json.NewDecoder(r.Body).Decode(&body)
		f.calls = append(f.calls, r.Method+" "+r.URL.Path)
	}
	switch p := r.URL.Path; {
	case r.Method == "GET" && p == "/api/open/site":
		var list []map[string]any
		for _, s := range f.sites {
			list = append(list, s)
		}
		ok(map[string]any{"data": list})
	case r.Method == "GET" && strings.HasPrefix(p, "/api/open/site/"):
		id, _ := strconv.Atoi(strings.TrimPrefix(p, "/api/open/site/"))
		ok(f.sites[id])
	case r.Method == "POST" && p == "/api/open/site":
		body["id"] = float64(f.next)
		body["is_enabled"] = true
		f.sites[f.next] = body
		f.next++
		ok(nil)
	case r.Method == "PUT" && p == "/api/open/site":
		f.sites[int(body["id"].(float64))] = body
		ok(nil)
	case r.Method == "DELETE" && p == "/api/open/site":
		delete(f.sites, int(body["ids"].([]any)[0].(float64)))
		ok(nil)
	case r.Method == "PUT" && p == "/api/open/site/mode":
		f.sites[int(body["ids"].([]any)[0].(float64))]["mode"] = body["mode"]
		ok(nil)
	case r.Method == "PUT" && p == "/api/open/site/enabled":
		f.sites[int(body["id"].(float64))]["is_enabled"] = body["enabled"]
		ok(nil)
	case r.Method == "GET" && p == "/api/open/cert":
		ok(map[string]any{"nodes": f.certs})
	case r.Method == "POST" && p == "/api/open/cert":
		f.certs = append(f.certs, map[string]any{"id": 2, "type": 2, "domains": []string{"new.example.ru"}, "valid_before": time.Now().Add(90 * 24 * time.Hour).Format(time.RFC3339)})
		ok(nil)
	default:
		readOnlySafeLine().ServeHTTP(w, r)
	}
}

func selfSignedPEM(t *testing.T) (string, string) {
	pk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "new.example.ru"},
		DNSNames: []string{"new.example.ru"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(90 * 24 * time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &pk.PublicKey, pk)
	kb, _ := x509.MarshalECPrivateKey(pk)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}))
}

func TestApps(t *testing.T) {
	fake := newSiteFake()
	ts, s, _ := newTestServerWith(t, fake)
	c := browser(ts)
	pw, _ := os.ReadFile(filepath.Join(s.Cfg.Web.DataDir, "initial-admin-password"))
	login(t, ts, c, "admin", strings.TrimSpace(string(pw)))

	code, page := get(t, ts, c, "/apps")
	if code != 200 || !strings.Contains(page, "im.example.ru") || !strings.Contains(page, "reachable") {
		t.Fatalf("apps page %d", code)
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
	form := func(names, ports, ups string, cert string) url.Values {
		return url.Values{"instance": {"prod"}, "comment": {"New"}, "names": {names}, "ports": {ports}, "upstreams": {ups},
			"cert_id": {cert}, "balance": {"1"}, "health_check": {"on"}, "reason": {"test"}}
	}

	// Rejected before anything reaches SafeLine.
	for name, v := range map[string]url.Values{
		"panel port":      form("new.example.ru", "12443 ssl", "http://10.0.0.5", "1"),
		"console port":    form("new.example.ru", "9443", "http://10.0.0.5", "0"),
		"ssl without crt": form("new.example.ru", "443 ssl", "http://10.0.0.5", "0"),
		"bad upstream":    form("new.example.ru", "80", "10.0.0.5", "0"),
		"bad domain":      form("new_example!", "80", "http://10.0.0.5", "0"),
		"duplicate host":  form("im.example.ru", "443 ssl", "http://10.0.0.5", "1"),
	} {
		if code, _ := post("/apps", v); code != http.StatusBadRequest {
			t.Errorf("%s: %d", name, code)
		}
	}
	noReason := form("new.example.ru", "80", "http://10.0.0.5", "0")
	noReason.Del("reason")
	if code, _ := post("/apps", noReason); code != http.StatusBadRequest {
		t.Errorf("no reason: %d", code)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("rejected forms wrote: %v", fake.calls)
	}

	if code, _ := post("/apps", form("new.example.ru\n*.new.example.ru", "80\n8443 ssl", "http://10.0.0.5:8080\nhttp://10.0.0.6:8080", "1")); code != http.StatusSeeOther {
		t.Fatalf("create: %d", code)
	}
	n := fake.sites[10]
	if n == nil || n["ports"].([]any)[1] != "8443_ssl" || n["type"].(float64) != 0 || len(n["upstreams"].([]any)) != 2 || n["mode"].(float64) != 2 {
		t.Fatalf("created site %+v", n)
	}
	if _, has := n["title"]; has || n["comment"] != "New" {
		t.Fatalf("name must go to comment, title is SafeLine's: %+v", n)
	}

	// Editing keeps fields the panel does not know and upstream weights.
	if code, page := get(t, ts, c, "/apps/prod/4/edit"); code != 200 || !strings.Contains(page, "https://10.0.0.12:443") {
		t.Fatalf("edit form %d", code)
	}
	if code, _ := post("/apps/prod/4", form("im.example.ru", "443 ssl", "https://10.0.0.12:443\nhttps://10.0.0.13:443", "1")); code != http.StatusSeeOther {
		t.Fatalf("update: %d", code)
	}
	upd := fake.sites[4]
	ups := upd["load_balance"].(map[string]any)["upstreams"].([]any)
	if upd["title"] != "IM" || upd["comment"] != "New" {
		t.Fatalf("title %v, comment %v", upd["title"], upd["comment"])
	}
	if upd["forbidden_html_path"] != "/custom/403.html" || len(ups) != 2 || ups[0].(map[string]any)["weight"].(float64) != 5 {
		t.Fatalf("update lost fields: %+v", upd)
	}
	if _, has := upd["health_state"]; has {
		t.Fatal("read-only field sent back")
	}

	// Disable and delete need the typed name.
	if code, _ := post("/apps/prod/4/enabled", url.Values{"enabled": {"0"}, "reason": {"x"}, "confirm": {"wrong"}}); code != http.StatusSeeOther || fake.sites[4]["is_enabled"] != true {
		t.Fatal("disabled without confirmation")
	}
	post("/apps/prod/4/enabled", url.Values{"enabled": {"0"}, "reason": {"x"}, "confirm": {"im.example.ru"}})
	if fake.sites[4]["is_enabled"] != false {
		t.Fatal("not disabled")
	}
	post("/apps/prod/10/delete", url.Values{"reason": {"x"}, "confirm": {"new.example.ru"}})
	if _, still := fake.sites[10]; still {
		t.Fatal("not deleted")
	}

	// Certificates: a mismatched pair is refused, a good one goes through,
	// a certificate in use cannot be deleted.
	crt, key := selfSignedPEM(t)
	_, otherKey := selfSignedPEM(t)
	if code, _ := post("/certs?instance=prod", url.Values{"crt": {crt}, "key": {otherKey}}); code != http.StatusBadRequest {
		t.Fatalf("mismatched key accepted: %d", code)
	}
	if code, _ := post("/certs?instance=prod", url.Values{"crt": {crt}, "key": {key}}); code != http.StatusSeeOther || len(fake.certs) != 2 {
		t.Fatalf("upload: %d", code)
	}
	if code, b := post("/certs/prod/1/delete", url.Values{}); code != http.StatusBadRequest || !strings.Contains(b, "is in use") {
		t.Fatalf("delete of used cert: %d", code)
	}
	_, certsPage := get(t, ts, c, "/certs")
	if strings.Contains(certsPage, "PRIVATE KEY-----\nM") {
		t.Fatal("key echoed")
	}
	_, audit := get(t, ts, c, "/audit")
	for _, want := range []string{"app.create", "app.update", "app.enabled", "app.delete", "cert.upload"} {
		if !strings.Contains(audit, want) {
			t.Errorf("audit misses %s", want)
		}
	}
}
