package safeline

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"wafpanel/internal/config"
)

func TestListRecords(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(tokenHeader) != "secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Path != "/api/open/records" || r.URL.Query().Get("page_size") != "2" {
			t.Errorf("unexpected request %s", r.URL)
		}
		w.Write([]byte(`{"err":null,"msg":"","data":{"total":2,"data":[
			{"event_id":"ev11","src_ip":"1.2.3.4","host":"a.example","url_path":"/x","dst_port":"443","attack_type":9,"action":1,"timestamp":1793354400},
			{"event_id":"ev10","ip":"5.6.7.8","url":"/y","attack_type":-3,"action":0,"timestamp":1793354400123}]}}`))
	}))
	defer srv.Close()

	// Pin the test server certificate the way ca_file pins a SafeLine console.
	ca := filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600)

	c, err := New(config.Instance{ID: "t", BaseURL: srv.URL, Token: "secret", CAFile: ca, Timeout: config.Duration(5 * time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	rows, err := c.ListRecords(context.Background(), 0, 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("got %d rows", len(rows))
	}
	r := rows[0]
	if r.EventID != "ev11" || r.DstPort != 443 || r.AttackType != 9 || !r.Denied() || r.Time.Unix() != 1793354400 {
		t.Fatalf("bad first row %+v", r)
	}
	r = rows[1]
	if r.SrcIP != "5.6.7.8" || r.URLPath != "/y" || r.Denied() || r.Time.UnixMilli() != 1793354400123 {
		t.Fatalf("bad second row %+v", r)
	}

	bad, _ := New(config.Instance{ID: "t", BaseURL: srv.URL, Token: "wrong", CAFile: ca, Timeout: config.Duration(5 * time.Second)})
	if _, err := bad.ListRecords(context.Background(), 0, 1, 2); err == nil {
		t.Fatal("wrong token accepted")
	}
}

func TestAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"err":"login-required","msg":"token invalid","data":null}`))
	}))
	defer srv.Close()
	c, _ := New(config.Instance{ID: "t", BaseURL: srv.URL, Token: "x", Timeout: config.Duration(time.Second)})
	if _, err := c.ListRecords(context.Background(), 0, 1, 1); err == nil {
		t.Fatal("API error not reported")
	}
}
