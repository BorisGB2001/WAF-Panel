// Package web is the panel UI: attack log, alerts, rules, users and audit.
package web

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"encoding/pem"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"wafpanel/internal/auth"
	"wafpanel/internal/blocklist"
	"wafpanel/internal/config"
	"wafpanel/internal/history"
	"wafpanel/internal/i18n"
	"wafpanel/internal/notify"
	"wafpanel/internal/safeline"
	"wafpanel/internal/stats"
)

//go:embed templates/*.html static/*
var assets embed.FS

const cookieName = "wafpanel_session"

// RuleSink receives rules saved in the UI, e.g. pipeline.Pipeline.
type RuleSink interface {
	SetRules([]config.Rule)
}

type Server struct {
	Cfg      *config.Config
	Clients  []*safeline.Client
	Senders  map[string]notify.Sender
	Stats    *stats.Registry
	History  *history.History
	Rules    RuleSink
	Log      *slog.Logger
	Version  string
	RuleFile string

	users    *auth.Users
	sessions *auth.Sessions
	audit    *auth.Audit
	throttle *auth.Throttle
	pages    map[string]map[string]*template.Template // lang -> page -> template

	mu         sync.Mutex
	rules      []config.Rule
	dash       map[string]*dashCache
	blocklists map[string]*blocklist.Manager
}

// Open prepares users, sessions and audit in the data dir. When no user
// exists an "admin" is created and its password written to
// <data_dir>/initial-admin-password.
func (s *Server) Open(rules []config.Rule) error {
	dir := s.Cfg.Web.DataDir
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	var err error
	if s.users, err = auth.OpenUsers(filepath.Join(dir, "users.json")); err != nil {
		return err
	}
	pwFile := filepath.Join(dir, "initial-admin-password")
	created, err := s.users.Bootstrap(pwFile)
	if err != nil {
		return err
	}
	if created {
		s.Log.Warn("created user admin; its password is in " + pwFile + ", change it after the first login")
	}
	if s.sessions, err = auth.OpenSessions(filepath.Join(dir, "session.key"), s.Cfg.Web.SessionTTL.D()); err != nil {
		return err
	}
	if s.audit, err = auth.OpenAudit(filepath.Join(dir, "audit.log"), 1000); err != nil {
		return err
	}
	s.throttle = auth.NewThrottle(5, 15*time.Minute)
	s.rules = rules
	s.dash = map[string]*dashCache{}
	return s.parseTemplates()
}

func (s *Server) parseTemplates() error {
	s.pages = map[string]map[string]*template.Template{}
	files, err := fs.Glob(assets, "templates/*.html")
	if err != nil {
		return err
	}
	for _, lang := range i18n.Langs {
		s.pages[lang] = map[string]*template.Template{}
		for _, f := range files {
			name := filepath.Base(f)
			if name == "layout.html" {
				continue
			}
			t, err := template.New(name).Funcs(funcs).Funcs(langFuncs(lang)).ParseFS(assets, "templates/layout.html", f)
			if err != nil {
				return fmt.Errorf("template %s: %w", name, err)
			}
			s.pages[lang][name] = t
		}
	}
	return nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	static, _ := fs.Sub(assets, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(static)))
	mux.HandleFunc("GET /login", s.loginPage)
	mux.HandleFunc("POST /login", s.loginPost)
	mux.HandleFunc("GET /lang/{lang}", s.setLang)

	view := func(p string, h handler) { mux.Handle(p, s.authed(h, false)) }
	admin := func(p string, h handler) { mux.Handle(p, s.authed(h, true)) }

	view("POST /logout", s.logout)
	view("GET /{$}", s.dashboard)
	view("GET /stats", s.statsPage)
	view("GET /stats/qps", s.statsQPS)
	view("GET /attacks", s.attacks)
	view("GET /attacks.csv", s.attacksCSV)
	view("GET /attacks/{instance}/{event}", s.attackDetail)
	view("GET /alerts", s.alerts)
	view("GET /rules", s.rulesPage)
	view("GET /channels", s.channelsPage)
	view("GET /waf", s.wafPage)
	view("GET /apps", s.appsPage)
	view("GET /policies", s.policiesPage)
	view("GET /certs", s.certsPage)
	view("GET /account", s.accountPage)
	view("POST /account/password", s.accountPassword)

	admin("POST /rules", s.rulesSave)
	admin("POST /channels/{name}/test", s.channelTest)
	admin("GET /users", s.usersPage)
	admin("POST /users", s.userAdd)
	admin("POST /users/{name}/role", s.userRole)
	admin("POST /users/{name}/password", s.userPassword)
	admin("POST /users/{name}/delete", s.userDelete)
	admin("GET /audit", s.auditPage)
	admin("GET /apps/new", s.appNew)
	admin("POST /apps", s.appSave)
	admin("GET /apps/{instance}/{id}/edit", s.appEdit)
	admin("POST /apps/{instance}/{id}", s.appSave)
	admin("POST /apps/{instance}/{id}/enabled", s.appEnabled)
	admin("POST /apps/{instance}/{id}/delete", s.appDelete)
	admin("POST /certs", s.certUpload)
	admin("POST /certs/{instance}/{id}", s.certUpload)
	admin("POST /certs/{instance}/{id}/delete", s.certDelete)
	admin("GET /policies/new", s.policyNew)
	admin("POST /policies", s.policySave)
	admin("GET /policies/{instance}/{id}/edit", s.policyEdit)
	admin("POST /policies/{instance}/{id}", s.policySave)
	admin("POST /policies/{instance}/{id}/enabled", s.policyEnabled)
	admin("POST /policies/{instance}/{id}/delete", s.policyDelete)
	admin("POST /waf/{instance}/block", s.wafBlock)
	admin("POST /waf/{instance}/unblock", s.wafUnblock)
	admin("POST /waf/{instance}/sites/{id}/mode", s.wafSiteMode)

	return securityHeaders(mux)
}

// ListenAndServe serves HTTPS until ctx ends.
func (s *Server) ListenAndServe(ctx context.Context) error {
	cert, key := s.Cfg.Web.TLSCert, s.Cfg.Web.TLSKey
	if cert == "" && !s.Cfg.Web.PlainHTTP {
		var err error
		if cert, key, err = selfSigned(filepath.Join(s.Cfg.Web.DataDir, "tls")); err != nil {
			return err
		}
	}
	srv := &http.Server{
		Addr:              s.Cfg.Web.Listen,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      120 * time.Second,
		IdleTimeout:       2 * time.Minute,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
		ErrorLog:          slog.NewLogLogger(s.Log.Handler(), slog.LevelWarn),
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(sctx)
	}()
	s.Log.Info("web panel listening", "addr", s.Cfg.Web.Listen, "tls", !s.Cfg.Web.PlainHTTP)
	var err error
	if s.Cfg.Web.PlainHTTP {
		err = srv.ListenAndServe()
	} else {
		cl := &certLoader{cert: cert, key: key}
		if _, err := cl.get(nil); err != nil {
			return err
		}
		srv.TLSConfig.GetCertificate = cl.get
		err = srv.ListenAndServeTLS("", "")
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// selfSigned creates (once) a certificate for the panel in dir.
func selfSigned(dir string) (string, string, error) {
	cert, key := filepath.Join(dir, "panel.crt"), filepath.Join(dir, "panel.key")
	if _, err := os.Stat(cert); err == nil {
		return cert, key, nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", "", err
	}
	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	host, _ := os.Hostname()
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "WAF Panel " + host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(3, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{host, "localhost"},
		IPAddresses:  localIPs(),
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &pk.PublicKey, pk)
	if err != nil {
		return "", "", err
	}
	kb, err := x509.MarshalECPrivateKey(pk)
	if err != nil {
		return "", "", err
	}
	if err := os.WriteFile(key, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return "", "", err
	}
	return cert, key, nil
}

func localIPs() []net.IP {
	ips := []net.IP{net.ParseIP("127.0.0.1")}
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && !n.IP.IsLoopback() && n.IP.To4() != nil {
			ips = append(ips, n.IP)
		}
	}
	return ips
}

func (s *Server) client(id string) *safeline.Client {
	for _, c := range s.Clients {
		if c.ID == id {
			return c
		}
	}
	return nil
}

func (s *Server) currentRules() []config.Rule {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]config.Rule(nil), s.rules...)
}

// certLoader re-reads the certificate when its file changes, so a renewed
// certificate (e.g. the one SafeLine keeps for its sites) needs no restart.
type certLoader struct {
	cert, key string
	mu        sync.Mutex
	loaded    *tls.Certificate
	mtime     time.Time
	checked   time.Time
}

func (c *certLoader) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.loaded != nil && time.Since(c.checked) < time.Minute {
		return c.loaded, nil
	}
	c.checked = time.Now()
	fi, err := os.Stat(c.cert)
	if err != nil {
		if c.loaded != nil {
			return c.loaded, nil
		}
		return nil, err
	}
	if c.loaded != nil && !fi.ModTime().After(c.mtime) {
		return c.loaded, nil
	}
	pair, err := tls.LoadX509KeyPair(c.cert, c.key)
	if err != nil {
		if c.loaded != nil {
			return c.loaded, nil
		}
		return nil, err
	}
	c.loaded, c.mtime = &pair, fi.ModTime()
	return c.loaded, nil
}
