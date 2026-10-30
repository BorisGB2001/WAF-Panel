package web

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"wafpanel/internal/i18n"

	"wafpanel/internal/safeline"
)

// reservedPorts are taken on the WAF host by the SafeLine console, its
// internal listener, the panel and SSH; a site on them would cut access.
var reservedPorts = map[int]string{22: "SSH", 9443: "the SafeLine console", 12443: "this panel", 65443: "an internal SafeLine port", 9188: "panel metrics"}

var hostRe = regexp.MustCompile(`^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

var balanceTypes = []struct {
	ID    int
	Label string
}{{1, "Round robin"}, {2, "Least connections"}, {3, "IP hash"}}

func splitList(s string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == '\n' || r == ',' || r == '\r' }) {
		if f = strings.TrimSpace(f); f != "" && !slices.Contains(out, f) {
			out = append(out, f)
		}
	}
	return out
}

// appForm is the form as typed, kept to re-render it after an error.
type appForm struct {
	Comment, Names, Ports, Upstreams string
	Balance, CertID                  int
	Mode                             int // initial mode of a new site
	HealthCheck                      bool
	Reason                           string
}

func formFromRequest(r *http.Request) appForm {
	f := appForm{Comment: strings.TrimSpace(r.FormValue("comment")),
		Names: r.FormValue("names"), Ports: r.FormValue("ports"), Upstreams: r.FormValue("upstreams"),
		HealthCheck: r.FormValue("health_check") == "on", Reason: strings.TrimSpace(r.FormValue("reason"))}
	f.Balance, _ = strconv.Atoi(r.FormValue("balance"))
	f.CertID, _ = strconv.Atoi(r.FormValue("cert_id"))
	f.Mode = 2
	if m, err := strconv.Atoi(r.FormValue("mode")); err == nil && m >= 0 && m <= 2 {
		f.Mode = m
	}
	return f
}

func formFromDetail(d safeline.SiteDetail) appForm {
	f := appForm{Comment: d.Str("comment"), Names: strings.Join(d.Strings("server_names"), "\n"),
		Upstreams: strings.Join(d.Strings("upstreams"), "\n"), CertID: d.Int("cert_id"), HealthCheck: d.Bool("health_check"), Balance: 1}
	var ports []string
	for _, p := range d.Strings("ports") {
		ports = append(ports, strings.Replace(p, "_ssl", " ssl", 1))
	}
	f.Ports = strings.Join(ports, "\n")
	if lb, ok := d["load_balance"].(map[string]any); ok {
		if bt, ok := lb["balance_type"].(float64); ok && bt > 0 {
			f.Balance = int(bt)
		}
	}
	return f
}

// spec validates the form against the instance's sites and certificates.
func (f appForm) spec(selfID int, sites []safeline.Site, certs []safeline.Cert) (safeline.SiteSpec, error) {
	s := safeline.SiteSpec{Comment: f.Comment, BalanceType: f.Balance, CertID: f.CertID, HealthCheck: f.HealthCheck}
	if s.BalanceType < 1 || s.BalanceType > 3 {
		s.BalanceType = 1
	}
	for _, n := range splitList(strings.ToLower(f.Names)) {
		if n != "*" && !hostRe.MatchString(n) {
			return s, i18n.Errorf("The domain %q is not valid", n)
		}
		s.ServerNames = append(s.ServerNames, n)
	}
	if len(s.ServerNames) == 0 {
		return s, i18n.Errorf("Give at least one domain (or * for any)")
	}
	ssl := false
	for _, p := range splitList(f.Ports) {
		fields := strings.Fields(strings.ReplaceAll(strings.ToLower(p), "_", " "))
		n, err := strconv.Atoi(fields[0])
		if err != nil || n < 1 || n > 65535 || len(fields) > 2 || (len(fields) == 2 && fields[1] != "ssl") {
			return s, i18n.Errorf("The port %q is not valid: use “80” or “443 ssl”", p)
		}
		if why, ok := reservedPorts[n]; ok {
			return s, i18n.Errorf("Port %d is taken: %s", n, why)
		}
		v := strconv.Itoa(n)
		if len(fields) == 2 {
			v += "_ssl"
			ssl = true
		}
		if slices.ContainsFunc(s.Ports, func(x string) bool { return strings.TrimSuffix(x, "_ssl") == strconv.Itoa(n) }) {
			return s, i18n.Errorf("Port %d is listed twice", n)
		}
		s.Ports = append(s.Ports, v)
	}
	if len(s.Ports) == 0 {
		return s, i18n.Errorf("Give at least one port")
	}
	if ssl {
		if !slices.ContainsFunc(certs, func(c safeline.Cert) bool { return c.ID == s.CertID }) {
			return s, i18n.Errorf("Choose a certificate for the ssl port")
		}
	} else {
		s.CertID = 0
	}
	for _, u := range splitList(f.Upstreams) {
		pu, err := url.Parse(u)
		if err != nil || (pu.Scheme != "http" && pu.Scheme != "https") || pu.Host == "" || (pu.Path != "" && pu.Path != "/") || pu.RawQuery != "" {
			return s, i18n.Errorf("Upstream %q: use an address like https://10.0.0.5:443", u)
		}
		s.Upstreams = append(s.Upstreams, pu.Scheme+"://"+pu.Host)
	}
	if len(s.Upstreams) == 0 {
		return s, i18n.Errorf("Give at least one upstream")
	}
	// The same domain on the same port in two sites is ambiguous for nginx.
	for _, other := range sites {
		if other.ID == selfID {
			continue
		}
		for _, n := range s.ServerNames {
			if !slices.Contains(other.ServerNames, n) {
				continue
			}
			for _, p := range s.Ports {
				pn := strings.TrimSuffix(p, "_ssl")
				if slices.ContainsFunc(other.Ports, func(x string) bool { return strings.TrimSuffix(x, "_ssl") == pn }) {
					return s, i18n.Errorf("The domain %s on port %s is already used by site #%d", n, pn, other.ID)
				}
			}
		}
	}
	return s, nil
}

type appRow struct {
	Site   safeline.Site
	Detail safeline.SiteDetail
	Health map[string]string
	Cert   *safeline.Cert
	Err    string
}

func (s *Server) instanceFrom(r *http.Request) *safeline.Client {
	if c := s.client(r.PathValue("instance")); c != nil {
		return c
	}
	if c := s.client(r.FormValue("instance")); c != nil {
		return c
	}
	return s.Clients[0]
}

func (s *Server) appsPage(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	c := s.instanceFrom(r)
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	p := page{Title: "Applications", Active: "apps"}
	sites, err := c.Sites(ctx)
	if err != nil {
		p.Error = "SafeLine: " + err.Error()
	}
	certs, _ := c.Certs(ctx)
	rows := make([]appRow, len(sites))
	var wg sync.WaitGroup
	for i, site := range sites {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rows[i].Site = site
			d, err := c.SiteDetail(ctx, site.ID)
			if err != nil {
				rows[i].Err = err.Error()
				return
			}
			rows[i].Detail, rows[i].Health = d, d.Health()
			for j := range certs {
				if certs[j].ID == d.Int("cert_id") && slices.ContainsFunc(site.Ports, func(x string) bool { return strings.HasSuffix(x, "_ssl") }) {
					rows[i].Cert = &certs[j]
				}
			}
		}()
	}
	wg.Wait()
	p.Data = map[string]any{"Instance": c, "Instances": s.Clients, "Rows": rows, "Certs": certs}
	s.render(w, r, rc, "apps.html", p)
}

func (s *Server) renderAppForm(w http.ResponseWriter, r *http.Request, rc *reqCtx, c *safeline.Client, id int, f appForm, errMsg string) {
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	certs, err := c.Certs(ctx)
	if err != nil && errMsg == "" {
		errMsg = "SafeLine: " + err.Error()
	}
	title := tr(r, "New application")
	if id != 0 {
		title = tr(r, "Application #%d", id)
	}
	if errMsg != "" {
		w.WriteHeader(http.StatusBadRequest)
	}
	s.render(w, r, rc, "app_form.html", page{Title: title, Active: "apps", Error: errMsg, Data: map[string]any{
		"Instance": c, "ID": id, "F": f, "Certs": certs, "Balances": balanceTypes,
	}})
}

func (s *Server) appNew(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	s.renderAppForm(w, r, rc, s.instanceFrom(r), 0, appForm{Ports: "80\n443 ssl", Balance: 1, Mode: 2, HealthCheck: true}, "")
}

func (s *Server) appEdit(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	c := s.instanceFrom(r)
	id, _ := strconv.Atoi(r.PathValue("id"))
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	d, err := c.SiteDetail(ctx, id)
	if err != nil || d.ID() != id {
		http.NotFound(w, r)
		return
	}
	if d.Int("type") != 0 {
		flashRedirect(w, r, "/apps?instance="+url.QueryEscape(c.ID), "", tr(r, "Sites of this type (static or redirect) are edited in the SafeLine console"))
		return
	}
	s.renderAppForm(w, r, rc, c, id, formFromDetail(d), "")
}

func (s *Server) appSave(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	c := s.instanceFrom(r)
	id, _ := strconv.Atoi(r.PathValue("id"))
	f := formFromRequest(r)
	if f.Reason == "" {
		s.renderAppForm(w, r, rc, c, id, f, tr(r, "Give a reason for the change — it goes to the audit log"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	sites, err := c.Sites(ctx)
	if err != nil {
		s.renderAppForm(w, r, rc, c, id, f, "SafeLine: "+err.Error())
		return
	}
	certs, _ := c.Certs(ctx)
	spec, err := f.spec(id, sites, certs)
	if err != nil {
		s.renderAppForm(w, r, rc, c, id, f, errText(r, err))
		return
	}
	action, verb := "app.create", "Application %s created"
	if id != 0 {
		action, verb = "app.update", "Application %s updated"
		err = c.UpdateSite(ctx, id, spec)
	} else if err = c.CreateSite(ctx, spec); err == nil {
		// SafeLine's default mode for a new site is not documented; set the
		// chosen one explicitly so a new site never starts blocking unasked.
		err = setNewSiteMode(ctx, c, spec.ServerNames, f.Mode)
	}
	detail := fmt.Sprintf("%s #%d %s ports %s → %s: %s", c.ID, id, strings.Join(spec.ServerNames, ","), strings.Join(spec.Ports, ","), strings.Join(spec.Upstreams, ","), f.Reason)
	if err != nil {
		s.audit.Log(rc.User.Name, clientIP(r), action+".failed", detail+" — "+err.Error())
		s.renderAppForm(w, r, rc, c, id, f, tr(r, "SafeLine rejected the change: %s", errText(r, err)))
		return
	}
	s.audit.Log(rc.User.Name, clientIP(r), action, detail)
	s.forgetDash(c.ID)
	flashRedirect(w, r, "/apps?instance="+url.QueryEscape(c.ID), tr(r, verb, strings.Join(spec.ServerNames, ", ")), "")
}

// confirmSite loads the site and checks the typed confirmation and reason.
func (s *Server) confirmSite(ctx context.Context, c *safeline.Client, r *http.Request) (safeline.SiteDetail, string, error) {
	id, _ := strconv.Atoi(r.PathValue("id"))
	d, err := c.SiteDetail(ctx, id)
	if err != nil || d.ID() != id {
		return nil, "", i18n.Errorf("Site not found")
	}
	name := d.Str("title")
	if ns := d.Strings("server_names"); len(ns) > 0 {
		name = ns[0]
	}
	if strings.TrimSpace(r.FormValue("reason")) == "" {
		return d, name, i18n.Errorf("Give a reason — it goes to the audit log")
	}
	if r.FormValue("confirm") != name {
		return d, name, i18n.Errorf("To confirm, type the site name: %s", name)
	}
	return d, name, nil
}

func (s *Server) appEnabled(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	c := s.instanceFrom(r)
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	d, name, err := s.confirmSite(ctx, c, r)
	back := "/apps?instance=" + url.QueryEscape(c.ID)
	if err != nil {
		flashRedirect(w, r, back, "", errText(r, err))
		return
	}
	on := r.FormValue("enabled") == "1"
	verb := map[bool]string{true: "enabled", false: "disabled"}[on]
	detail := fmt.Sprintf("%s #%d %s %s: %s", c.ID, d.ID(), name, verb, r.FormValue("reason"))
	if err := c.SetSiteEnabled(ctx, d.ID(), on); err != nil {
		s.audit.Log(rc.User.Name, clientIP(r), "app.enabled.failed", detail+" — "+err.Error())
		flashRedirect(w, r, back, "", "SafeLine: "+err.Error())
		return
	}
	s.audit.Log(rc.User.Name, clientIP(r), "app.enabled", detail)
	s.forgetDash(c.ID)
	flashRedirect(w, r, back, tr(r, "Site %s "+verb, name), "")
}

func (s *Server) appDelete(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	c := s.instanceFrom(r)
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	d, name, err := s.confirmSite(ctx, c, r)
	back := "/apps?instance=" + url.QueryEscape(c.ID)
	if err != nil {
		flashRedirect(w, r, back, "", errText(r, err))
		return
	}
	detail := fmt.Sprintf("%s #%d %s (%s → %s): %s", c.ID, d.ID(), name, strings.Join(d.Strings("ports"), ","), strings.Join(d.Strings("upstreams"), ","), r.FormValue("reason"))
	if err := c.DeleteSite(ctx, d.ID()); err != nil {
		s.audit.Log(rc.User.Name, clientIP(r), "app.delete.failed", detail+" — "+err.Error())
		flashRedirect(w, r, back, "", "SafeLine: "+err.Error())
		return
	}
	s.audit.Log(rc.User.Name, clientIP(r), "app.delete", detail)
	s.forgetDash(c.ID)
	flashRedirect(w, r, back, tr(r, "Site %s deleted", name), "")
}

func (s *Server) forgetDash(id string) {
	s.mu.Lock()
	delete(s.dash, id)
	s.mu.Unlock()
}

// ---------- certificates ----------

func (s *Server) certsPage(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	s.renderCerts(w, r, rc, s.instanceFrom(r), "", "")
}

func (s *Server) renderCerts(w http.ResponseWriter, r *http.Request, rc *reqCtx, c *safeline.Client, flash, errMsg string) {
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	certs, err := c.Certs(ctx)
	if err != nil && errMsg == "" {
		errMsg = "SafeLine: " + err.Error()
	}
	if errMsg != "" && r.Method == http.MethodPost {
		w.WriteHeader(http.StatusBadRequest)
	}
	s.render(w, r, rc, "certs.html", page{Title: "Certificates", Active: "apps", Flash: flash, Error: errMsg,
		Data: map[string]any{"Instance": c, "Certs": certs}})
}

// checkPEM makes sure the pair loads and returns its names and expiry.
func checkPEM(crt, key string) (string, error) {
	pair, err := tls.X509KeyPair([]byte(crt), []byte(key))
	if err != nil {
		return "", i18n.Errorf("The certificate and key do not match or are damaged: %v", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return "", err
	}
	if time.Now().After(leaf.NotAfter) {
		return "", i18n.Errorf("The certificate expired on %s", leaf.NotAfter.Format("2006-01-02"))
	}
	if b, _ := pem.Decode([]byte(crt)); b == nil {
		return "", i18n.Errorf("The certificate must be PEM")
	}
	return fmt.Sprintf("%s until %s", strings.Join(leaf.DNSNames, ","), leaf.NotAfter.Format("2006-01-02")), nil
}

func (s *Server) certUpload(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	c := s.instanceFrom(r)
	id, _ := strconv.Atoi(r.PathValue("id"))
	crt, key := strings.TrimSpace(r.FormValue("crt"))+"\n", strings.TrimSpace(r.FormValue("key"))+"\n"
	info, err := checkPEM(crt, key)
	if err != nil {
		s.renderCerts(w, r, rc, c, "", errText(r, err))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	action := "cert.upload"
	if id != 0 {
		action = "cert.replace"
	}
	detail := fmt.Sprintf("%s #%d %s", c.ID, id, info)
	if err := c.UploadCert(ctx, id, crt, key); err != nil {
		s.audit.Log(rc.User.Name, clientIP(r), action+".failed", detail+" — "+err.Error())
		s.renderCerts(w, r, rc, c, "", tr(r, "SafeLine rejected the certificate: %s", err))
		return
	}
	s.audit.Log(rc.User.Name, clientIP(r), action, detail)
	flashRedirect(w, r, "/certs?instance="+url.QueryEscape(c.ID), tr(r, "Certificate uploaded: %s", info), "")
}

func (s *Server) certDelete(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	c := s.instanceFrom(r)
	id, _ := strconv.Atoi(r.PathValue("id"))
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	certs, err := c.Certs(ctx)
	if err != nil {
		s.renderCerts(w, r, rc, c, "", "SafeLine: "+err.Error())
		return
	}
	i := slices.IndexFunc(certs, func(x safeline.Cert) bool { return x.ID == id })
	if i < 0 {
		http.NotFound(w, r)
		return
	}
	if len(certs[i].RelatedSites) > 0 {
		s.renderCerts(w, r, rc, c, "", tr(r, "The certificate is in use: %s. Change it on these sites first.", strings.Join(certs[i].RelatedSites, ", ")))
		return
	}
	detail := fmt.Sprintf("%s #%d %s", c.ID, id, strings.Join(certs[i].Domains, ","))
	if err := c.DeleteCert(ctx, id); err != nil {
		s.audit.Log(rc.User.Name, clientIP(r), "cert.delete.failed", detail+" — "+err.Error())
		s.renderCerts(w, r, rc, c, "", "SafeLine: "+err.Error())
		return
	}
	s.audit.Log(rc.User.Name, clientIP(r), "cert.delete", detail)
	flashRedirect(w, r, "/certs?instance="+url.QueryEscape(c.ID), tr(r, "Certificate deleted"), "")
}

func setNewSiteMode(ctx context.Context, c *safeline.Client, names []string, mode int) error {
	sites, err := c.Sites(ctx)
	if err != nil {
		return fmt.Errorf("the site was created but its mode was not set: %w", err)
	}
	for _, x := range sites {
		if slices.Equal(x.ServerNames, names) {
			if x.Mode == mode {
				return nil
			}
			if err := c.SetSiteMode(ctx, x.ID, mode); err != nil {
				return fmt.Errorf("site #%d was created but its mode was not set: %w", x.ID, err)
			}
			return nil
		}
	}
	return errors.New("the site was created but is not in the list — check its mode by hand")
}
