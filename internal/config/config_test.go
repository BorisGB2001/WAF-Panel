package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestExampleConfig keeps deploy/wafpanel.example.yaml loadable.
func TestExampleConfig(t *testing.T) {
	dir := t.TempDir()
	b, err := os.ReadFile("../../deploy/wafpanel.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "alerts.yaml"), b, 0o600)
	os.Mkdir(filepath.Join(dir, "secrets"), 0o700)
	for _, f := range []string{"prod.token", "prod-ca.pem", "telegram.token", "smtp.password", "webhook.secret"} {
		os.WriteFile(filepath.Join(dir, "secrets", f), []byte("x\n"), 0o600)
	}
	c, err := Load(filepath.Join(dir, "alerts.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Instances[0].Token != "x" || c.Instances[0].TLSServerName != "waf.example.com" || c.Instances[0].Lookback.D() != 2*time.Minute {
		t.Fatalf("instance %+v", c.Instances[0])
	}
	if r := c.Rules[1]; r.Cooldown.D() != 15*time.Minute || r.GroupBy != "src_ip" {
		t.Fatalf("rule defaults %+v", r)
	}
	if c.SIEM[0].QueueSize != 10000 || c.Channels[1].Email.Password != "x" {
		t.Fatal("defaults not applied")
	}
	if len(c.Block.ProtectedNets) != 1 || c.Block.ProtectedNets[0].String() != "192.0.2.0/24" {
		t.Fatalf("block.protected %v", c.Block.ProtectedNets)
	}
}

func TestPrefixes(t *testing.T) {
	ps, err := prefixes([]string{"192.0.2.7", "198.51.100.9/24", " 2001:db8::1 "})
	if err != nil || len(ps) != 3 || ps[0].String() != "192.0.2.7/32" || ps[1].String() != "198.51.100.0/24" || ps[2].Bits() != 128 {
		t.Fatal(ps, err)
	}
	if _, err := prefixes([]string{"office"}); err == nil {
		t.Fatal("a name accepted as a network")
	}
}

func TestRejectsUnknownChannel(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "t"), []byte("x"), 0o600)
	os.WriteFile(filepath.Join(dir, "c.yaml"), []byte(`
instances: [{id: a, base_url: "https://h:9443", token_file: t}]
rules: [{name: r, channels: [nope]}]
`), 0o600)
	if _, err := Load(filepath.Join(dir, "c.yaml")); err == nil {
		t.Fatal("unknown channel accepted")
	}
}

func TestPlainHTTPOnlyOnLoopback(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "t"), []byte("x"), 0o600)
	for listen, ok := range map[string]bool{"127.0.0.1:8080": true, "localhost:8080": true, "0.0.0.0:12443": false, "10.0.0.1:80": false} {
		os.WriteFile(filepath.Join(dir, "c.yaml"), []byte(`
instances: [{id: a, base_url: "https://h:9443", token_file: t}]
web: {listen: "`+listen+`", plain_http: true}
`), 0o600)
		_, err := Load(filepath.Join(dir, "c.yaml"))
		if (err == nil) != ok {
			t.Errorf("%s: err=%v", listen, err)
		}
	}
}
