// Package analytics builds traffic statistics from the logs SafeLine's
// tengine writes on the host: one access log per site and the shared
// error log. SafeLine CE keeps only 24 hours of statistics and leaves
// locations, clients, response codes, referrers and pages empty; the logs
// have all of it.
package analytics

import (
	"errors"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// Access is one line of a SafeLine site access log:
//
//	$remote_addr | $remote_user | $time_local | "$host" | "$request" | $status | $body_bytes_sent | "$http_referer" | "$http_user_agent"
type Access struct {
	IP       string
	Time     time.Time
	Host     string
	Method   string
	Path     string // without the query
	Status   int
	Bytes    int64
	Referer  string
	UA       string
	Protocol string
}

var errFormat = errors.New("not a SafeLine access log line")

func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		s = s[1 : len(s)-1]
	}
	if s == "-" {
		return ""
	}
	return s
}

// ParseAccess reads one access log line. Quoted fields may contain " | "
// (a user agent or a URL can), so the fixed fields are taken from both
// ends and the request from the middle.
func ParseAccess(line string) (Access, error) {
	var a Access
	f := strings.Split(strings.TrimRight(line, "\r\n"), " | ")
	if len(f) < 9 {
		return a, errFormat
	}
	// Head: ip, user, time, host. Tail: status, bytes, referer, ua — the
	// user agent is the only field that may contain the separator at the
	// end, so join everything after the referer back.
	head, rest := f[:4], f[4:]
	var err error
	if a.Time, err = time.Parse("02/Jan/2006:15:04:05 -0700", strings.TrimSpace(head[2])); err != nil {
		return a, errFormat
	}
	a.IP = strings.TrimSpace(head[0])
	a.Host = strings.ToLower(unquote(head[3]))
	// The status is the first purely numeric field after the request.
	si := -1
	for i := 1; i < len(rest)-2; i++ {
		if n, err := strconv.Atoi(strings.TrimSpace(rest[i])); err == nil && n >= 100 && n < 600 {
			if _, err := strconv.ParseInt(strings.TrimSpace(rest[i+1]), 10, 64); err == nil {
				si = i
				break
			}
		}
	}
	if si < 0 {
		return a, errFormat
	}
	req := unquote(strings.Join(rest[:si], " | "))
	a.Status, _ = strconv.Atoi(strings.TrimSpace(rest[si]))
	a.Bytes, _ = strconv.ParseInt(strings.TrimSpace(rest[si+1]), 10, 64)
	a.Referer = unquote(rest[si+2])
	if si+3 < len(rest) {
		a.UA = unquote(strings.Join(rest[si+3:], " | "))
	}
	// "GET /path?q HTTP/1.1"; a garbage request line stays whole in Path.
	if parts := strings.SplitN(req, " ", 3); len(parts) == 3 && isMethod(parts[0]) {
		a.Method, a.Path, a.Protocol = parts[0], parts[1], parts[2]
	} else {
		a.Method, a.Path = "-", req
	}
	if i := strings.IndexByte(a.Path, '?'); i >= 0 {
		a.Path = a.Path[:i]
	}
	if _, err := netip.ParseAddr(a.IP); err != nil {
		return a, errFormat
	}
	return a, nil
}

func isMethod(s string) bool {
	if len(s) < 3 || len(s) > 16 {
		return false
	}
	for _, r := range s {
		if r < 'A' || r > 'Z' {
			return false
		}
	}
	return true
}

// UpstreamError is a failure of tengine to talk to a site's upstream.
type UpstreamError struct {
	Time     time.Time
	Kind     string // see errorKinds
	Server   string // server_name of the site
	Upstream string // host:port
	Client   string
}

// errorKinds classify nginx error log messages, most specific first.
var errorKinds = []struct{ match, kind string }{
	{"upstream timed out", "timeout"},
	{"no live upstreams", "no live upstreams"},
	{"connect() failed", "connection failed"},
	{"upstream prematurely closed", "closed by upstream"},
	{"recv() failed", "connection reset"},
	{"SSL_do_handshake() failed", "TLS handshake"},
	{"upstream sent too big header", "header too big"},
	{"upstream sent invalid", "invalid response"},
	{"client intended to send too large body", "request body too large"},
}

// ParseError reads one error log line and keeps upstream problems only:
// warnings, notices and messages that are not about a request are skipped.
func ParseError(line string) (UpstreamError, bool) {
	var e UpstreamError
	if len(line) < 20 {
		return e, false
	}
	lvl := strings.Index(line, " [")
	if lvl < 0 {
		return e, false
	}
	end := strings.IndexByte(line[lvl+2:], ']')
	if end < 0 {
		return e, false
	}
	switch line[lvl+2 : lvl+2+end] {
	case "error", "crit", "alert", "emerg":
	default:
		return e, false
	}
	t, err := time.ParseInLocation("2006/01/02 15:04:05", line[:lvl], time.Local)
	if err != nil {
		return e, false
	}
	e.Time = t
	for _, k := range errorKinds {
		if strings.Contains(line, k.match) {
			e.Kind = k.kind
			break
		}
	}
	if e.Kind == "" {
		return e, false
	}
	e.Server = field(line, "server: ")
	e.Client = field(line, "client: ")
	if up := field(line, "upstream: "); up != "" {
		up = strings.Trim(up, `"`)
		if strings.HasPrefix(up, "unix:") || strings.Contains(up, "://unix:") {
			up = "unix socket"
		} else if i := strings.Index(up, "://"); i >= 0 {
			up = up[i+3:]
		}
		if i := strings.IndexByte(up, '/'); i >= 0 {
			up = up[:i]
		}
		e.Upstream = up
	}
	return e, true
}

// field returns the value after key up to the next ", ".
func field(line, key string) string {
	i := strings.Index(line, key)
	if i < 0 {
		return ""
	}
	v := line[i+len(key):]
	if j := strings.Index(v, ", "); j >= 0 {
		v = v[:j]
	}
	return strings.TrimSpace(v)
}
