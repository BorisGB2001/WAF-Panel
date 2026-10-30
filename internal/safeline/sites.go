package safeline

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// SiteDetail is the full site object of GET /api/open/site/{id}. It is kept
// as a map so an update sends back every field the panel does not edit
// (error pages, Anti-Bot, log limits, ...) unchanged, as the console does.
type SiteDetail map[string]any

func (d SiteDetail) ID() int              { return int(num(d, "id")) }
func (d SiteDetail) Str(k string) string  { return str(d, k) }
func (d SiteDetail) Int(k string) int     { return int(num(d, k)) }
func (d SiteDetail) Int64(k string) int64 { return num(d, k) }
func (d SiteDetail) Bool(k string) bool   { b, _ := d[k].(bool); return b }

func (d SiteDetail) Strings(k string) []string {
	var out []string
	if xs, ok := d[k].([]any); ok {
		for _, x := range xs {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

// Health returns upstream -> ("ok" | error text).
func (d SiteDetail) Health() map[string]string {
	out := map[string]string{}
	hs, _ := d["health_state"].(map[string]any)
	for up, v := range hs {
		m, _ := v.(map[string]any)
		switch {
		case str(m, "error") != "":
			out[up] = str(m, "error")
		case num(m, "state") == 2:
			out[up] = "ok"
		default:
			out[up] = "state " + str(m, "state")
		}
	}
	return out
}

func (c *Client) SiteDetail(ctx context.Context, id int) (SiteDetail, error) {
	var d SiteDetail
	err := c.get(ctx, "/api/open/site/"+strconv.Itoa(id), nil, &d)
	return d, err
}

// SiteSpec is what the panel edits on a reverse-proxy site.
type SiteSpec struct {
	Title       string
	Comment     string
	ServerNames []string
	Ports       []string // "80", "443_ssl"
	Upstreams   []string
	BalanceType int // 1 round robin, 2 least conn, 3 ip hash
	CertID      int
	HealthCheck bool
}

func (s SiteSpec) apply(d SiteDetail) {
	d["title"] = s.Title
	d["comment"] = s.Comment
	d["server_names"] = s.ServerNames
	d["ports"] = s.Ports
	d["upstreams"] = s.Upstreams
	// Keep weight and role of upstreams that stay, so an edit in the panel
	// does not undo a primary/backup setup made in the console.
	old := map[string]map[string]any{}
	if lb, ok := d["load_balance"].(map[string]any); ok {
		if xs, ok := lb["upstreams"].([]any); ok {
			for _, x := range xs {
				if m, ok := x.(map[string]any); ok {
					old[str(m, "address")] = m
				}
			}
		}
	}
	ups := make([]map[string]any, len(s.Upstreams))
	for i, u := range s.Upstreams {
		ups[i] = map[string]any{"address": u, "weight": 1, "role": "primary"}
		if m, ok := old[u]; ok {
			if w := num(m, "weight"); w > 0 {
				ups[i]["weight"] = w
			}
			if r := str(m, "role"); r != "" {
				ups[i]["role"] = r
			}
		}
	}
	bt := s.BalanceType
	if bt == 0 {
		bt = 1
	}
	d["load_balance"] = map[string]any{"balance_type": bt, "upstreams": ups}
	d["cert_id"] = s.CertID
	d["health_check"] = s.HealthCheck
}

// CreateSite adds a reverse-proxy site with the console's defaults.
func (c *Client) CreateSite(ctx context.Context, s SiteSpec) error {
	d := SiteDetail{
		"description": "", "email": "", "type": 0, "index": "", "static_default": 1,
		"redirect_status_code": 301, "health_check_interval": 60,
	}
	s.apply(d)
	return c.send(ctx, http.MethodPost, "/api/open/site", d, nil)
}

// UpdateSite re-reads the site and changes only the fields of s.
func (c *Client) UpdateSite(ctx context.Context, id int, s SiteSpec) error {
	d, err := c.SiteDetail(ctx, id)
	if err != nil {
		return err
	}
	if d.ID() != id {
		return fmt.Errorf("site %d not found", id)
	}
	s.apply(d)
	// Read-only and runtime fields the console does not send back.
	for _, k := range []string{"health_state", "created_at", "updated_at", "req_value", "denied_value",
		"tamper_refresh", "tamper_refresh_state", "runtime_enabled", "over_license_limit", "requested_enabled"} {
		delete(d, k)
	}
	return c.send(ctx, http.MethodPut, "/api/open/site", d, nil)
}

func (c *Client) DeleteSite(ctx context.Context, id int) error {
	return c.send(ctx, http.MethodDelete, "/api/open/site", map[string]any{"ids": []int{id}}, nil)
}

func (c *Client) SetSiteEnabled(ctx context.Context, id int, enabled bool) error {
	return c.send(ctx, http.MethodPut, "/api/open/site/enabled", map[string]any{"id": id, "enabled": enabled}, nil)
}

// Cert is an entry of the certificate list; the key is never read.
type Cert struct {
	ID           int      `json:"id"`
	Type         int      `json:"type"` // 2 uploaded, 3 ACME
	Domains      []string `json:"domains"`
	Issuer       string   `json:"issuer"`
	RelatedSites []string `json:"related_sites"`
	Expired      bool     `json:"expired"`
	Revoked      bool     `json:"revoked"`
	Trusted      bool     `json:"trusted"`
	ValidBefore  string   `json:"valid_before"`
	ACMEMessage  string   `json:"acme_message"`
}

func (c Cert) Expires() time.Time {
	t, _ := time.Parse(time.RFC3339, c.ValidBefore)
	return t
}

// DaysLeft is negative for an expired certificate.
func (c Cert) DaysLeft() int {
	return int(time.Until(c.Expires()).Hours() / 24)
}

func (c *Client) Certs(ctx context.Context) ([]Cert, error) {
	var data struct {
		Nodes []Cert `json:"nodes"`
	}
	err := c.get(ctx, "/api/open/cert", url.Values{}, &data)
	return data.Nodes, err
}

// UploadCert adds a certificate (id 0) or replaces an uploaded one.
func (c *Client) UploadCert(ctx context.Context, id int, crt, key string) error {
	body := map[string]any{"type": 2, "manual": map[string]string{"crt": crt, "key": key}}
	if id != 0 {
		body["id"] = id
	}
	return c.send(ctx, http.MethodPost, "/api/open/cert", body, nil)
}

func (c *Client) DeleteCert(ctx context.Context, id int) error {
	return c.send(ctx, http.MethodDelete, "/api/open/cert/"+strconv.Itoa(id), nil, nil)
}

// MarshalJSON keeps SiteDetail a plain JSON object.
func (d SiteDetail) MarshalJSON() ([]byte, error) { return json.Marshal(map[string]any(d)) }
