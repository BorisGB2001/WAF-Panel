package web

import (
	"bytes"
	"html/template"
	"net/http"
	"strings"
	"time"

	"wafpanel/internal/auth"
	"wafpanel/internal/i18n"
	"wafpanel/internal/safeline"
)

// page is the data every template gets; Data holds the page's own values.
type page struct {
	Lang    string
	Theme   string // "light", "dark" or "" to follow the system
	Here    string // this page, for the language and theme switches to come back to
	Title   string
	Active  string
	User    auth.User
	IsAdmin bool
	CSRF    string
	Flash   string
	Error   string
	Version string
	Now     time.Time
	Data    any
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, rc *reqCtx, name string, p page) {
	p.Lang, p.Theme = langOf(r), themeOf(r)
	p.Here = r.URL.Path
	if q := r.URL.Query(); r.Method == http.MethodGet && len(q) > 0 {
		q.Del("ok") // a flash message is shown once
		q.Del("err")
		if len(q) > 0 {
			p.Here += "?" + q.Encode()
		}
	}
	t := s.pages[p.Lang][name]
	if t == nil {
		http.Error(w, "no template "+name, http.StatusInternalServerError)
		return
	}
	if rc != nil {
		p.User = rc.User
		p.IsAdmin = rc.User.Role == auth.RoleAdmin
		p.CSRF = rc.CSRF
	}
	if p.Flash == "" {
		p.Flash = r.URL.Query().Get("ok")
	}
	if p.Error == "" {
		p.Error = r.URL.Query().Get("err")
	}
	p.Title = i18n.T(p.Lang, p.Title)
	p.Version = s.Version
	p.Now = time.Now()
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "layout", p); err != nil {
		s.Log.Error("render", "page", name, "err", err)
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(buf.Bytes())
}

var funcs = template.FuncMap{
	"hasSuffix":  strings.HasSuffix,
	"trimSuffix": strings.TrimSuffix,
	"num":        compact,
	"bytes":      humanBytes,
	"join":       func(s []string, sep string) string { return strings.Join(s, sep) },
	"pct": func(a, b int) int {
		if b == 0 {
			return 0
		}
		return a * 100 / b
	},
	"pct64": func(a, b int64) int64 {
		if b == 0 {
			return 0
		}
		return a * 100 / b
	},
	"add": func(a, b int) int { return a + b },
	"sub": func(a, b int) int { return a - b },
	"cut": func(s string, n int) string {
		r := []rune(s)
		if len(r) <= n {
			return s
		}
		return string(r[:n]) + "…"
	},
	"sevclass": func(s string) string {
		switch s {
		case "critical":
			return "bad"
		case "warning":
			return "warn"
		}
		return "info"
	},
	"deliveryclass": func(s string) string {
		switch s {
		case "ok":
			return "good"
		case "queued":
			return "info"
		}
		return "bad"
	},
}

// flashRedirect redirects back with a message shown once on the next page.
func flashRedirect(w http.ResponseWriter, r *http.Request, to, ok, errMsg string) {
	sep := "?"
	if strings.Contains(to, "?") {
		sep = "&"
	}
	switch {
	case errMsg != "":
		to += sep + "err=" + urlQuery(errMsg)
	case ok != "":
		to += sep + "ok=" + urlQuery(ok)
	}
	http.Redirect(w, r, to, http.StatusSeeOther)
}

const langCookie = "wafpanel_lang"

// langOf is the reader's language: the cookie set by /lang/{lang}, English
// otherwise.
func langOf(r *http.Request) string {
	if c, err := r.Cookie(langCookie); err == nil && i18n.Valid(c.Value) {
		return c.Value
	}
	return i18n.EN
}

// tr translates a message for the reader of r.
func tr(r *http.Request, s string, args ...any) string { return i18n.T(langOf(r), s, args...) }

// errText renders an error for the reader of r.
func errText(r *http.Request, err error) string { return i18n.Text(langOf(r), err) }

func (s *Server) setLang(w http.ResponseWriter, r *http.Request) {
	lang := r.PathValue("lang")
	if !i18n.Valid(lang) {
		http.NotFound(w, r)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: langCookie, Value: lang, Path: "/", MaxAge: 365 * 24 * 3600,
		HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, safeNext(r.URL.Query().Get("next")), http.StatusSeeOther)
}

const themeCookie = "wafpanel_theme"

// themeOf is the reader's colour theme; empty follows the system setting.
func themeOf(r *http.Request) string {
	if c, err := r.Cookie(themeCookie); err == nil && (c.Value == "light" || c.Value == "dark") {
		return c.Value
	}
	return ""
}

func (s *Server) setTheme(w http.ResponseWriter, r *http.Request) {
	theme := r.PathValue("theme")
	switch theme {
	case "light", "dark":
		http.SetCookie(w, &http.Cookie{Name: themeCookie, Value: theme, Path: "/", MaxAge: 365 * 24 * 3600,
			HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode})
	case "system":
		http.SetCookie(w, &http.Cookie{Name: themeCookie, Path: "/", MaxAge: -1,
			HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode})
	default:
		http.NotFound(w, r)
		return
	}
	http.Redirect(w, r, safeNext(r.URL.Query().Get("next")), http.StatusSeeOther)
}

// langFuncs are the template functions bound to one language.
func langFuncs(lang string) template.FuncMap {
	return template.FuncMap{
		"t":         func(s string, args ...any) string { return i18n.T(lang, s, args...) },
		"atype":     func(t int) string { return i18n.T(lang, safeline.AttackTypeCode(t)) },
		"atypeName": func(code string) string { return i18n.T(lang, code) },
		"dt": func(t time.Time) string {
			if t.IsZero() {
				return "—"
			}
			if lang == i18n.RU {
				return t.Local().Format("02.01.2006 15:04:05")
			}
			return t.Local().Format("2006-01-02 15:04:05")
		},
		"ago": func(t time.Time) string {
			if t.IsZero() {
				return i18n.T(lang, "never")
			}
			d := time.Since(t)
			switch {
			case d < time.Minute:
				return i18n.T(lang, "%d s ago", int(d.Seconds()))
			case d < time.Hour:
				return i18n.T(lang, "%d min ago", int(d.Minutes()))
			case d < 48*time.Hour:
				return i18n.T(lang, "%d h ago", int(d.Hours()))
			}
			return i18n.T(lang, "%d days ago", int(d.Hours()/24))
		},
	}
}
