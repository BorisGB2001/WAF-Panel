package web

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"wafpanel/internal/blocklist"
	"wafpanel/internal/safeline"
)

type ttlOption struct {
	Key   string
	Label string
	D     time.Duration
}

var blockTTLs = []ttlOption{
	{"1h", "1 hour", time.Hour}, {"24h", "24 hours", 24 * time.Hour}, {"7d", "7 days", 7 * 24 * time.Hour},
	{"30d", "30 days", 30 * 24 * time.Hour}, {"0", "Permanent", 0},
}

var siteModes = []struct {
	Mode  int
	Label string
	Hint  string
}{
	{0, "Defense", "attacks are blocked"},
	{2, "Monitoring", "attacks are only recorded, nothing is blocked"},
	{1, "Offline", "the site is closed to every visitor"},
}

// blocklists are created lazily, one per instance.
func (s *Server) blocklist(c *safeline.Client) *blocklist.Manager {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.blocklists == nil {
		s.blocklists = map[string]*blocklist.Manager{}
	}
	if m := s.blocklists[c.ID]; m != nil {
		return m
	}
	m := &blocklist.Manager{Instance: c.ID, API: c, Log: s.Log,
		File: filepath.Join(s.Cfg.Web.DataDir, "blocklist-"+c.ID+".json")}
	// Never let the panel lock out the WAF itself.
	for _, in := range s.Cfg.Instances {
		if in.ID != c.ID {
			continue
		}
		if u, err := url.Parse(in.BaseURL); err == nil {
			if a, err := netip.ParseAddr(u.Hostname()); err == nil {
				m.Protected = append(m.Protected, netip.PrefixFrom(a, a.BitLen()))
			}
		}
	}
	s.blocklists[c.ID] = m
	return m
}

// StartExpiry removes expired blocks on every instance until ctx ends.
func (s *Server) StartExpiry(ctx context.Context) {
	for _, c := range s.Clients {
		m := s.blocklist(c)
		go m.RunExpiry(ctx, func(ip string, err error) {
			detail := c.ID + " " + ip
			if err != nil {
				detail += ": " + err.Error()
				s.Log.Error("block expiry failed", "instance", c.ID, "ip", ip, "err", err)
			}
			s.audit.Log("system", "", "waf.unblock.expired", detail)
		})
	}
}

func (s *Server) wafPage(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	s.renderWAF(w, r, rc, "", "")
}

func (s *Server) renderWAF(w http.ResponseWriter, r *http.Request, rc *reqCtx, flash, errMsg string) {
	c := s.client(r.URL.Query().Get("instance"))
	if c == nil {
		c = s.client(r.PathValue("instance"))
	}
	if c == nil {
		c = s.Clients[0]
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()

	data := map[string]any{"Instance": c, "Instances": s.Clients, "TTLs": blockTTLs, "Modes": siteModes,
		"Prefill": r.URL.Query().Get("block"), "MyIP": clientIP(r)}
	var errs []string
	if sites, err := c.Sites(ctx); err != nil {
		errs = append(errs, tr(r, "sites")+": "+err.Error())
	} else {
		data["Sites"] = sites
		dry := 0
		for _, x := range sites {
			if x.Enabled && x.Mode == 2 {
				dry++
			}
		}
		data["DryRun"] = dry
	}
	if st, err := s.blocklist(c).Status(ctx); err != nil {
		errs = append(errs, tr(r, "blocklist")+": "+err.Error())
	} else {
		data["Block"] = st
	}
	if gs, err := c.IPGroups(ctx); err != nil {
		errs = append(errs, tr(r, "IP groups")+": "+err.Error())
	} else {
		data["Groups"] = gs
	}
	if errMsg == "" && len(errs) > 0 {
		errMsg = "SafeLine: " + strings.Join(errs, "; ")
	}
	s.render(w, r, rc, "waf.html", page{Title: "WAF control", Active: "waf", Flash: flash, Error: errMsg, Data: data})
}

func (s *Server) wafBlock(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	c := s.client(r.PathValue("instance"))
	if c == nil {
		http.NotFound(w, r)
		return
	}
	m := s.blocklist(c)
	ip, err := m.Normalize(strings.TrimSpace(r.FormValue("ip")), clientIP(r))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		s.renderWAF(w, r, rc, "", errText(r, err))
		return
	}
	reason := strings.TrimSpace(r.FormValue("reason"))
	if reason == "" {
		w.WriteHeader(http.StatusBadRequest)
		s.renderWAF(w, r, rc, "", tr(r, "Give a reason for the block — it goes to the audit log"))
		return
	}
	idx := slices.IndexFunc(blockTTLs, func(t ttlOption) bool { return t.Key == r.FormValue("ttl") })
	if idx < 0 {
		w.WriteHeader(http.StatusBadRequest)
		s.renderWAF(w, r, rc, "", tr(r, "Unknown block duration"))
		return
	}
	ttl := blockTTLs[idx]
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	err = m.Block(ctx, ip, reason, rc.User.Name, ttl.D)
	detail := fmt.Sprintf("%s %s for %s: %s", c.ID, ip, ttl.Label, reason)
	if err != nil {
		s.audit.Log(rc.User.Name, clientIP(r), "waf.block.failed", detail+" — "+err.Error())
		w.WriteHeader(http.StatusBadGateway)
		s.renderWAF(w, r, rc, "", tr(r, "SafeLine rejected the block: %s", err))
		return
	}
	s.audit.Log(rc.User.Name, clientIP(r), "waf.block", detail)
	flashRedirect(w, r, "/waf?instance="+url.QueryEscape(c.ID), tr(r, "Blocked %s (%s)", ip, tr(r, ttl.Label)), "")
}

func (s *Server) wafUnblock(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	c := s.client(r.PathValue("instance"))
	if c == nil {
		http.NotFound(w, r)
		return
	}
	ip := r.FormValue("ip")
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	if err := s.blocklist(c).Unblock(ctx, ip); err != nil {
		s.audit.Log(rc.User.Name, clientIP(r), "waf.unblock.failed", c.ID+" "+ip+" — "+err.Error())
		w.WriteHeader(http.StatusBadGateway)
		s.renderWAF(w, r, rc, "", tr(r, "SafeLine rejected the unblock: %s", err))
		return
	}
	s.audit.Log(rc.User.Name, clientIP(r), "waf.unblock", c.ID+" "+ip)
	flashRedirect(w, r, "/waf?instance="+url.QueryEscape(c.ID), tr(r, "Unblocked %s", ip), "")
}

func (s *Server) wafSiteMode(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	c := s.client(r.PathValue("instance"))
	if c == nil {
		http.NotFound(w, r)
		return
	}
	id, _ := strconv.Atoi(r.PathValue("id"))
	mode, err := strconv.Atoi(r.FormValue("mode"))
	if err != nil || mode < 0 || mode > 2 {
		w.WriteHeader(http.StatusBadRequest)
		s.renderWAF(w, r, rc, "", tr(r, "Unknown mode"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	sites, err := c.Sites(ctx)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		s.renderWAF(w, r, rc, "", "SafeLine: "+err.Error())
		return
	}
	i := slices.IndexFunc(sites, func(x safeline.Site) bool { return x.ID == id })
	if i < 0 {
		http.NotFound(w, r)
		return
	}
	site := sites[i]
	name := site.Title
	if len(site.ServerNames) > 0 {
		name = site.ServerNames[0]
	}
	reason := strings.TrimSpace(r.FormValue("reason"))
	switch {
	case site.Mode == mode:
		s.renderWAF(w, r, rc, "", tr(r, "The site is already in this mode"))
		return
	case reason == "":
		w.WriteHeader(http.StatusBadRequest)
		s.renderWAF(w, r, rc, "", tr(r, "Give a reason for the mode change — it goes to the audit log"))
		return
	case r.FormValue("confirm") != name:
		w.WriteHeader(http.StatusBadRequest)
		s.renderWAF(w, r, rc, "", tr(r, "To confirm, type the site name: %s", name))
		return
	}
	modeName := safeline.Site{Mode: mode}.ModeName()
	detail := fmt.Sprintf("%s site %s: %s → %s: %s", c.ID, name, site.ModeName(), modeName, reason)
	if err := c.SetSiteMode(ctx, id, mode); err != nil {
		s.audit.Log(rc.User.Name, clientIP(r), "waf.site_mode.failed", detail+" — "+err.Error())
		w.WriteHeader(http.StatusBadGateway)
		s.renderWAF(w, r, rc, "", tr(r, "SafeLine rejected the mode change: %s", err))
		return
	}
	s.audit.Log(rc.User.Name, clientIP(r), "waf.site_mode", detail)
	s.mu.Lock()
	delete(s.dash, c.ID)
	s.mu.Unlock()
	flashRedirect(w, r, "/waf?instance="+url.QueryEscape(c.ID), tr(r, "Site %s switched to %s", name, tr(r, modeName)), "")
}
