// Package safeline is a read-only client of the SafeLine CE OpenAPI.
package safeline

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"wafpanel/internal/config"
)

const tokenHeader = "X-SLCE-API-TOKEN"

type Client struct {
	ID   string
	Name string

	base  *url.URL
	token string
	hc    *http.Client
}

func New(in config.Instance) (*Client, error) {
	base, err := url.Parse(strings.TrimRight(in.BaseURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("instance %s: %w", in.ID, err)
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: in.TLSServerName}
	if in.CAFile != "" {
		pem, err := os.ReadFile(in.CAFile)
		if err != nil {
			return nil, fmt.Errorf("instance %s: ca_file: %w", in.ID, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("instance %s: ca_file has no PEM certificate", in.ID)
		}
		tlsCfg.RootCAs = pool
	}
	return &Client{
		ID:    in.ID,
		Name:  in.Name,
		base:  base,
		token: in.Token,
		hc: &http.Client{
			Timeout:   in.Timeout.D(),
			Transport: &http.Transport{TLSClientConfig: tlsCfg},
			// The token is a custom header that net/http would replay to any
			// host a redirect names, so only same-origin redirects are followed.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if req.URL.Scheme != base.Scheme || req.URL.Host != base.Host || len(via) > 5 {
					return fmt.Errorf("refusing redirect to %s", req.URL.Redacted())
				}
				return nil
			},
		},
	}, nil
}

// envelope is the response wrapper of every SafeLine API call.
type envelope struct {
	Err  json.RawMessage `json:"err"`
	Msg  string          `json:"msg"`
	Data json.RawMessage `json:"data"`
}

func (c *Client) get(ctx context.Context, path string, q url.Values, out any) error {
	u := *c.base
	u.Path += path
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set(tokenHeader, c.token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "wafpanel/1")
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: HTTP %d: %.300s", path, resp.StatusCode, body)
	}
	var env envelope
	if err := json.Unmarshal(body, &env); err != nil {
		return fmt.Errorf("GET %s: %w", path, err)
	}
	if e := strings.TrimSpace(string(env.Err)); e != "" && e != "null" && e != `""` {
		return fmt.Errorf("GET %s: %s %s", path, e, env.Msg)
	}
	return json.Unmarshal(env.Data, out)
}

// ListRecords returns one page of attack records with timestamp >= since
// (Unix milliseconds, 0 for all), newest first.
func (c *Client) ListRecords(ctx context.Context, since int64, page, size int) ([]Record, error) {
	f := RecordFilter{Page: page, Size: size}
	if since > 0 {
		f.Start = time.UnixMilli(since)
	}
	rows, _, err := c.SearchRecords(ctx, f)
	return rows, err
}

// RecordFilter mirrors the filters of the SafeLine attack log.
type RecordFilter struct {
	IP          string
	Host        string
	URL         string
	EventID     string
	AttackTypes []int
	Action      string // "deny", "pass" or "" for both
	Start, End  time.Time
	Page, Size  int
}

// SearchRecords returns one page of matching records and the total count.
func (c *Client) SearchRecords(ctx context.Context, f RecordFilter) ([]Record, int64, error) {
	var data struct {
		Total int64             `json:"total"`
		Data  []json.RawMessage `json:"data"`
		Nodes []json.RawMessage `json:"nodes"`
	}
	q := url.Values{"page": {strconv.Itoa(max(f.Page, 1))}, "page_size": {strconv.Itoa(max(f.Size, 1))}}
	set := func(k, v string) {
		if v != "" {
			q.Set(k, v)
		}
	}
	set("ip", f.IP)
	set("host", f.Host)
	set("url", f.URL)
	set("event_id", f.EventID)
	if len(f.AttackTypes) > 0 {
		ts := make([]string, len(f.AttackTypes))
		for i, t := range f.AttackTypes {
			ts[i] = strconv.Itoa(t)
		}
		q.Set("attack_type", strings.Join(ts, ","))
	}
	switch f.Action {
	case "deny":
		q.Set("action", "1")
	case "pass":
		q.Set("action", "0")
	}
	if !f.Start.IsZero() {
		q.Set("start", strconv.FormatInt(f.Start.UnixMilli(), 10))
	}
	if !f.End.IsZero() {
		q.Set("end", strconv.FormatInt(f.End.UnixMilli(), 10))
	}
	if err := c.get(ctx, "/api/open/records", q, &data); err != nil {
		return nil, 0, err
	}
	rows := data.Data
	if rows == nil {
		rows = data.Nodes
	}
	out := make([]Record, 0, len(rows))
	for _, raw := range rows {
		r, err := parseRecord(raw)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, r)
	}
	return out, data.Total, nil
}

// RecordDetail returns one record with request and response in Raw
// (req_header, req_body, rsp_header, rsp_body, payload, ...).
func (c *Client) RecordDetail(ctx context.Context, eventID string) (Record, error) {
	var raw json.RawMessage
	if err := c.get(ctx, "/api/open/record/"+url.PathEscape(eventID), nil, &raw); err != nil {
		return Record{}, err
	}
	return parseRecord(raw)
}

// Site is a protected application as configured in SafeLine.
type Site struct {
	ID          int      `json:"id"`
	ServerNames []string `json:"server_names"`
	Ports       []string `json:"ports"`
	Upstreams   []string `json:"upstreams"`
	Enabled     bool     `json:"is_enabled"`
	Mode        int      `json:"mode"`
	Title       string   `json:"title"`
	Comment     string   `json:"comment"`
}

// ModeName follows SiteRunMode of the console.
func (s Site) ModeName() string {
	switch s.Mode {
	case 0:
		return "Defense"
	case 1:
		return "Offline"
	case 2:
		return "Monitoring"
	}
	return "Mode " + strconv.Itoa(s.Mode)
}

func (c *Client) Sites(ctx context.Context) ([]Site, error) {
	var data struct {
		Data []Site `json:"data"`
	}
	q := url.Values{"page": {"1"}, "page_size": {"100"}}
	if err := c.get(ctx, "/api/open/site", q, &data); err != nil {
		return nil, err
	}
	return data.Data, nil
}

// Health checks /api/open/health, which needs no token.
func (c *Client) Health(ctx context.Context) error {
	u := *c.base
	u.Path += "/api/open/health"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health: HTTP %d", resp.StatusCode)
	}
	return nil
}
