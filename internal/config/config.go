// Package config loads the YAML configuration of the alerting service.
package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Duration is a time.Duration that is written as "30s" or "5m" in YAML.
type Duration time.Duration

func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	v, err := time.ParseDuration(n.Value)
	if err != nil {
		return fmt.Errorf("line %d: %w", n.Line, err)
	}
	*d = Duration(v)
	return nil
}

func (d Duration) D() time.Duration { return time.Duration(d) }

type Config struct {
	// StateFile keeps the per-instance cursor so a restart neither repeats
	// nor skips events.
	StateFile string `yaml:"state_file"`
	// Language of alert texts: "en" (default) or "ru".
	Language  string     `yaml:"language"`
	HTTP      HTTP       `yaml:"http"`
	Web       Web        `yaml:"web"`
	Instances []Instance `yaml:"instances"`
	Channels  []Channel  `yaml:"channels"`
	Rules     []Rule     `yaml:"rules"`
	SIEM      []SIEM     `yaml:"siem"`
	Analytics Analytics  `yaml:"analytics"`
}

// Analytics builds traffic statistics from the logs of SafeLine instances
// on this host (see Instance.Logs).
type Analytics struct {
	// GeoIPDB is a MaxMind-format City or Country database; without it
	// only private and public addresses are told apart. The installer
	// copies the GeoLite2-City.mmdb of SafeLine's detector image.
	GeoIPDB string `yaml:"geoip_db"`
	// Retention of daily statistics, 90 days by default.
	Retention Duration `yaml:"retention"`
	// Backfill reads the rotated logs still on disk on the first start.
	Backfill *bool `yaml:"backfill"`
}

// Logs of a SafeLine installation on this host.
type Logs struct {
	// AccessDir holds tengine's accesslog_<site id>, e.g.
	// /data/safeline/logs/nginx/safeline.
	AccessDir string `yaml:"access_dir"`
	// ErrorLog is tengine's error log, e.g.
	// /data/safeline/logs/nginx/error.log.
	ErrorLog string `yaml:"error_log"`
}

type HTTP struct {
	// Listen serves /healthz and /metrics. Empty disables it.
	Listen string `yaml:"listen"`
}

// Web is the panel UI.
type Web struct {
	// Listen enables the UI, e.g. "0.0.0.0:12443". Empty disables it.
	Listen string `yaml:"listen"`
	// TLSCert and TLSKey; when empty a self-signed certificate is created
	// in DataDir/tls on the first start.
	TLSCert string `yaml:"tls_cert"`
	TLSKey  string `yaml:"tls_key"`
	// DataDir keeps users, the session key, rules edited in the UI, the
	// alert history and the audit log.
	DataDir    string   `yaml:"data_dir"`
	SessionTTL Duration `yaml:"session_ttl"`
	// PlainHTTP serves without TLS. Only allowed on a loopback listen
	// address: for local development or behind a reverse proxy on the host.
	PlainHTTP bool `yaml:"plain_http"`
}

// Instance is one SafeLine installation reached over its OpenAPI.
type Instance struct {
	ID        string `yaml:"id"`
	Name      string `yaml:"name"`
	BaseURL   string `yaml:"base_url"`
	TokenFile string `yaml:"token_file"`
	// CAFile pins the self-signed certificate of the SafeLine console.
	CAFile string `yaml:"ca_file"`
	// TLSServerName verifies the certificate against this name when
	// base_url is an IP, e.g. a public wildcard cert on an internal address.
	TLSServerName string   `yaml:"tls_server_name"`
	PollInterval  Duration `yaml:"poll_interval"`
	// Lookback is how far behind the newest record each poll re-reads to
	// catch records that reach the API late. 2m by default.
	Lookback Duration `yaml:"lookback"`
	Timeout  Duration `yaml:"timeout"`
	PageSize int      `yaml:"page_size"`
	// MaxPages bounds one poll; more new events than PageSize*MaxPages
	// means some of them are skipped and a warning is logged.
	MaxPages int `yaml:"max_pages"`
	// Backfill emits the events already present on the first start.
	// Off by default so a new deployment does not flood the channels.
	Backfill bool `yaml:"backfill"`
	// Logs enables traffic analytics when SafeLine runs on this host.
	Logs Logs `yaml:"logs"`

	Token string `yaml:"-"`
}

type Channel struct {
	Name     string    `yaml:"name"`
	Type     string    `yaml:"type"` // telegram | email | webhook
	Telegram *Telegram `yaml:"telegram"`
	Email    *Email    `yaml:"email"`
	Webhook  *Webhook  `yaml:"webhook"`
}

type Telegram struct {
	BotTokenFile string `yaml:"bot_token_file"`
	ChatID       string `yaml:"chat_id"`
	ThreadID     int64  `yaml:"thread_id"`
	// APIURL overrides https://api.telegram.org, e.g. for a local Bot API server.
	APIURL string `yaml:"api_url"`

	BotToken string `yaml:"-"`
}

type Email struct {
	Host         string   `yaml:"host"`
	Port         int      `yaml:"port"`
	TLS          string   `yaml:"tls"` // starttls | tls | none
	Username     string   `yaml:"username"`
	PasswordFile string   `yaml:"password_file"`
	From         string   `yaml:"from"`
	To           []string `yaml:"to"`

	Password string `yaml:"-"`
}

type Webhook struct {
	URL     string            `yaml:"url"`
	Format  string            `yaml:"format"` // json | slack
	Headers map[string]string `yaml:"headers"`
	// SecretFile enables an X-WAFPanel-Signature HMAC-SHA256 header.
	SecretFile string `yaml:"secret_file"`

	Secret string `yaml:"-"`
}

// Rule turns matching events into alerts.
type Rule struct {
	Name     string `yaml:"name"`
	Disabled bool   `yaml:"disabled,omitempty"`
	Severity string `yaml:"severity,omitempty"` // info | warning | critical

	// Filters; an empty list matches everything.
	Instances   []string `yaml:"instances,omitempty"`
	Hosts       []string `yaml:"hosts,omitempty"` // exact host or "*.example.com"
	AttackTypes []int    `yaml:"attack_types,omitempty"`
	Actions     []string `yaml:"actions,omitempty"` // deny | pass
	MinRisk     int      `yaml:"min_risk,omitempty"`

	// Threshold events of one group within Window fire one alert.
	// Threshold 1 alerts on every event (still subject to Cooldown).
	Threshold int      `yaml:"threshold"`
	Window    Duration `yaml:"window,omitempty"`
	GroupBy   string   `yaml:"group_by,omitempty"` // src_ip | host | instance | none
	Cooldown  Duration `yaml:"cooldown,omitempty"`

	Channels []string `yaml:"channels"`
}

// SIEM forwards every event (not alerts) to a syslog receiver.
type SIEM struct {
	Name    string `yaml:"name"`
	Network string `yaml:"network"` // udp | tcp | tls
	Address string `yaml:"address"`
	Format  string `yaml:"format"`  // cef | json
	Framing string `yaml:"framing"` // newline | octet (tcp/tls only)
	// Header is the syslog header before the message. Wazuh does not
	// pre-decode RFC 5424 and decodes JSON only without a header, so it
	// needs "none" with format json.
	Header string `yaml:"header"` // rfc5424 | none
	// JSONRaw adds the whole SafeLine record under "raw" in the json format.
	JSONRaw bool   `yaml:"json_raw"`
	CAFile  string `yaml:"ca_file"`
	// Facility is a syslog facility number, 16 (local0) by default.
	Facility   int      `yaml:"facility"`
	Hostname   string   `yaml:"hostname"`
	AppName    string   `yaml:"app_name"`
	Instances  []string `yaml:"instances"`
	OnlyDenied bool     `yaml:"only_denied"`
	QueueSize  int      `yaml:"queue_size"`
}

// Load reads path, expands ${ENV} references and reads secret files.
// Relative file paths are resolved from the directory of path.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	dec := yaml.NewDecoder(strings.NewReader(os.ExpandEnv(string(raw))))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := c.finish(filepath.Dir(path)); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) finish(dir string) error {
	abs := func(p string) string {
		if p == "" || filepath.IsAbs(p) {
			return p
		}
		return filepath.Join(dir, p)
	}
	secret := func(p, what string) (string, error) {
		if p == "" {
			return "", nil
		}
		b, err := os.ReadFile(abs(p))
		if err != nil {
			return "", fmt.Errorf("%s: %w", what, err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	var err error

	if c.Language == "" {
		c.Language = "en"
	}
	if c.Language != "en" && c.Language != "ru" {
		return fmt.Errorf("language must be en or ru")
	}
	if c.StateFile == "" {
		c.StateFile = "state.json"
	}
	c.StateFile = abs(c.StateFile)

	if c.Web.DataDir == "" {
		c.Web.DataDir = filepath.Dir(c.StateFile)
	}
	c.Web.DataDir = abs(c.Web.DataDir)
	c.Web.TLSCert = abs(c.Web.TLSCert)
	c.Web.TLSKey = abs(c.Web.TLSKey)
	if (c.Web.TLSCert == "") != (c.Web.TLSKey == "") {
		return fmt.Errorf("web: tls_cert and tls_key go together")
	}
	if c.Web.PlainHTTP {
		host, _, err := net.SplitHostPort(c.Web.Listen)
		if ip := net.ParseIP(host); err != nil || (host != "localhost" && (ip == nil || !ip.IsLoopback())) {
			return fmt.Errorf("web: plain_http is only allowed on a loopback listen address")
		}
	}
	if c.Web.SessionTTL == 0 {
		c.Web.SessionTTL = Duration(12 * time.Hour)
	}

	c.Analytics.GeoIPDB = abs(c.Analytics.GeoIPDB)
	if c.Analytics.Retention == 0 {
		c.Analytics.Retention = Duration(90 * 24 * time.Hour)
	}
	if c.Analytics.Retention.D() < 48*time.Hour {
		return fmt.Errorf("analytics: retention must be at least 48h")
	}
	if c.Analytics.Backfill == nil {
		yes := true
		c.Analytics.Backfill = &yes
	}

	if len(c.Instances) == 0 {
		return fmt.Errorf("no instances configured")
	}
	ids := map[string]bool{}
	for i := range c.Instances {
		in := &c.Instances[i]
		if in.ID == "" || ids[in.ID] {
			return fmt.Errorf("instance #%d: id is empty or duplicated", i+1)
		}
		ids[in.ID] = true
		if in.Name == "" {
			in.Name = in.ID
		}
		in.Logs.AccessDir, in.Logs.ErrorLog = abs(in.Logs.AccessDir), abs(in.Logs.ErrorLog)
		if !strings.HasPrefix(in.BaseURL, "https://") && !strings.HasPrefix(in.BaseURL, "http://127.0.0.1") && !strings.HasPrefix(in.BaseURL, "http://localhost") {
			return fmt.Errorf("instance %s: base_url must be https (the API token travels in a header)", in.ID)
		}
		in.CAFile = abs(in.CAFile)
		if in.Token, err = secret(in.TokenFile, "instance "+in.ID+" token_file"); err != nil {
			return err
		}
		if in.Token == "" {
			return fmt.Errorf("instance %s: token_file is required", in.ID)
		}
		if in.PollInterval == 0 {
			in.PollInterval = Duration(15 * time.Second)
		}
		if in.Lookback == 0 {
			in.Lookback = Duration(2 * time.Minute)
		}
		if in.Timeout == 0 {
			in.Timeout = Duration(20 * time.Second)
		}
		if in.PageSize == 0 {
			in.PageSize = 100
		}
		if in.MaxPages == 0 {
			in.MaxPages = 20
		}
	}

	chans := map[string]bool{}
	for i := range c.Channels {
		ch := &c.Channels[i]
		if ch.Name == "" || chans[ch.Name] {
			return fmt.Errorf("channel #%d: name is empty or duplicated", i+1)
		}
		chans[ch.Name] = true
		switch ch.Type {
		case "telegram":
			if ch.Telegram == nil || ch.Telegram.ChatID == "" {
				return fmt.Errorf("channel %s: telegram.chat_id is required", ch.Name)
			}
			if ch.Telegram.BotToken, err = secret(ch.Telegram.BotTokenFile, "channel "+ch.Name+" bot_token_file"); err != nil {
				return err
			}
			if ch.Telegram.BotToken == "" {
				return fmt.Errorf("channel %s: telegram.bot_token_file is required", ch.Name)
			}
		case "email":
			e := ch.Email
			if e == nil || e.Host == "" || e.From == "" || len(e.To) == 0 {
				return fmt.Errorf("channel %s: email.host, from and to are required", ch.Name)
			}
			if e.TLS == "" {
				e.TLS = "starttls"
			}
			if e.Port == 0 {
				e.Port = map[string]int{"tls": 465, "starttls": 587, "none": 25}[e.TLS]
			}
			if e.Password, err = secret(e.PasswordFile, "channel "+ch.Name+" password_file"); err != nil {
				return err
			}
		case "webhook":
			if ch.Webhook == nil || ch.Webhook.URL == "" {
				return fmt.Errorf("channel %s: webhook.url is required", ch.Name)
			}
			if ch.Webhook.Format == "" {
				ch.Webhook.Format = "json"
			}
			if ch.Webhook.Secret, err = secret(ch.Webhook.SecretFile, "channel "+ch.Name+" secret_file"); err != nil {
				return err
			}
		default:
			return fmt.Errorf("channel %s: unknown type %q", ch.Name, ch.Type)
		}
	}

	if err := c.ValidateRules(c.Rules); err != nil {
		return err
	}

	for i := range c.SIEM {
		s := &c.SIEM[i]
		if s.Name == "" {
			s.Name = fmt.Sprintf("siem-%d", i+1)
		}
		if s.Address == "" {
			return fmt.Errorf("siem %s: address is required", s.Name)
		}
		if s.Network == "" {
			s.Network = "udp"
		}
		if s.Network != "udp" && s.Network != "tcp" && s.Network != "tls" {
			return fmt.Errorf("siem %s: network must be udp, tcp or tls", s.Name)
		}
		if s.Format == "" {
			s.Format = "cef"
		}
		if s.Format != "cef" && s.Format != "json" {
			return fmt.Errorf("siem %s: format must be cef or json", s.Name)
		}
		if s.Framing == "" {
			s.Framing = "newline"
		}
		if s.Framing != "newline" && s.Framing != "octet" {
			return fmt.Errorf("siem %s: framing must be newline or octet", s.Name)
		}
		if s.Header == "" {
			s.Header = "rfc5424"
		}
		if s.Header != "rfc5424" && s.Header != "none" {
			return fmt.Errorf("siem %s: header must be rfc5424 or none", s.Name)
		}
		if s.Facility == 0 {
			s.Facility = 16
		}
		if s.AppName == "" {
			s.AppName = "safeline"
		}
		if s.QueueSize == 0 {
			s.QueueSize = 10000
		}
		s.CAFile = abs(s.CAFile)
		for _, n := range s.Instances {
			if !ids[n] {
				return fmt.Errorf("siem %s: unknown instance %q", s.Name, n)
			}
		}
	}
	return nil
}

// ValidateRules checks rules against the configured channels and instances
// and fills in defaults. The web UI uses it before saving edited rules.
func (c *Config) ValidateRules(rules []Rule) error {
	chans := map[string]bool{}
	for _, ch := range c.Channels {
		chans[ch.Name] = true
	}
	ids := map[string]bool{}
	for _, in := range c.Instances {
		ids[in.ID] = true
	}
	names := map[string]bool{}
	for i := range rules {
		r := &rules[i]
		if r.Name == "" {
			return fmt.Errorf("rule #%d: name is required", i+1)
		}
		if names[r.Name] {
			return fmt.Errorf("rule %s: duplicated name", r.Name)
		}
		names[r.Name] = true
		if len(r.Channels) == 0 {
			return fmt.Errorf("rule %s: no channels", r.Name)
		}
		for _, n := range r.Channels {
			if !chans[n] {
				return fmt.Errorf("rule %s: unknown channel %q", r.Name, n)
			}
		}
		for _, n := range r.Instances {
			if !ids[n] {
				return fmt.Errorf("rule %s: unknown instance %q", r.Name, n)
			}
		}
		for _, a := range r.Actions {
			if a != "deny" && a != "pass" {
				return fmt.Errorf("rule %s: action must be deny or pass, got %q", r.Name, a)
			}
		}
		if r.Threshold <= 0 {
			r.Threshold = 1
		}
		if r.Threshold > 1 && r.Window == 0 {
			return fmt.Errorf("rule %s: window is required when threshold > 1", r.Name)
		}
		if r.GroupBy == "" {
			r.GroupBy = "src_ip"
		}
		if r.GroupBy != "src_ip" && r.GroupBy != "host" && r.GroupBy != "instance" && r.GroupBy != "none" {
			return fmt.Errorf("rule %s: unknown group_by %q", r.Name, r.GroupBy)
		}
		if r.Cooldown == 0 {
			r.Cooldown = r.Window
		}
		if r.Severity == "" {
			r.Severity = "warning"
		}
		if r.Severity != "info" && r.Severity != "warning" && r.Severity != "critical" {
			return fmt.Errorf("rule %s: severity must be info, warning or critical", r.Name)
		}
	}
	return nil
}

// MarshalYAML writes a Duration back as "5m".
func (d Duration) MarshalYAML() (any, error) { return d.String(), nil }

// String is time.Duration without the zero tails: "5m" instead of "5m0s".
func (d Duration) String() string {
	s := time.Duration(d).String()
	if strings.HasSuffix(s, "m0s") {
		s = s[:len(s)-2]
	}
	if strings.HasSuffix(s, "h0m") {
		s = s[:len(s)-2]
	}
	return s
}
