// Command wafpanel is the WAF Panel: it watches SafeLine instances, sends
// alerts, forwards events to SIEM and serves the web UI.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"wafpanel/internal/analytics"
	"wafpanel/internal/auth"
	"wafpanel/internal/autoban"
	"wafpanel/internal/collector"
	"wafpanel/internal/config"
	"wafpanel/internal/history"
	"wafpanel/internal/notify"
	"wafpanel/internal/pipeline"
	"wafpanel/internal/rules"
	"wafpanel/internal/safeline"
	"wafpanel/internal/siem"
	"wafpanel/internal/state"
	"wafpanel/internal/stats"
	"wafpanel/internal/web"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	cfgPath := flag.String("config", "/etc/wafpanel/wafpanel.yaml", "path to the configuration file")
	check := flag.Bool("check", false, "validate the config, read one page of records from every instance and exit")
	testChannel := flag.String("test-channel", "", "send a test alert to the named channel and exit")
	dryRun := flag.Bool("dry-run", false, "log alerts instead of sending them; nothing goes to SIEM")
	resetPassword := flag.String("reset-password", "", "set a random password for the named panel user, print it and exit")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if *resetPassword != "" {
		if err := runResetPassword(*cfgPath, *resetPassword); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if err := run(*cfgPath, *check, *testChannel, *dryRun, log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(cfgPath string, check bool, testChannel string, dryRun bool, log *slog.Logger) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	notify.Lang = cfg.Language
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	clients := make([]*safeline.Client, 0, len(cfg.Instances))
	for _, in := range cfg.Instances {
		c, err := safeline.New(in)
		if err != nil {
			return err
		}
		clients = append(clients, c)
	}
	if check {
		return runCheck(ctx, clients)
	}

	hc := &http.Client{Timeout: 30 * time.Second}
	st := stats.New()
	if testChannel != "" {
		return runTestChannel(ctx, cfg, testChannel, hc)
	}

	store, err := state.Open(cfg.StateFile)
	if err != nil {
		return fmt.Errorf("state: %w", err)
	}

	if err := os.MkdirAll(cfg.Web.DataDir, 0o700); err != nil {
		return err
	}
	hist, err := history.Open(filepath.Join(cfg.Web.DataDir, "alerts-history.jsonl"), 1000)
	if err != nil {
		return fmt.Errorf("history: %w", err)
	}
	ruleFile := filepath.Join(cfg.Web.DataDir, "rules.yaml")
	activeRules, err := loadRules(cfg, ruleFile)
	if err != nil {
		return err
	}

	senders := map[string]notify.Sender{}
	channels := map[string]pipeline.AlertSink{}
	for _, ch := range cfg.Channels {
		s, err := notify.NewSender(ch, hc)
		if err != nil {
			return err
		}
		senders[ch.Name] = s
		q := &notify.Queue{Name: ch.Name, Sender: s, Log: log, Stats: st, Retries: 4, Backoff: 5 * time.Second, OnResult: hist.Delivered}
		q.Start(ctx, 1000)
		channels[ch.Name] = q
	}
	var targets []*siem.Syslog
	for _, sc := range cfg.SIEM {
		s, err := siem.NewSyslog(sc, log, st)
		if err != nil {
			return err
		}
		s.Start(ctx)
		targets = append(targets, s)
	}

	events := make(chan safeline.Event, 1000)
	p := &pipeline.Pipeline{Engine: rules.New(activeRules), Channels: channels, SIEM: targets, History: hist, Log: log, DryRun: dryRun}

	// The auto-ban reads every event and access line; the web panel, which
	// owns the blocklists, applies its decisions.
	var ab *autoban.Engine
	decisions := make(chan autoban.Decision, 1000)
	queue := func(d *autoban.Decision) {
		if d == nil {
			return
		}
		select {
		case decisions <- *d:
		default:
			log.Warn("auto-ban: queue full, decision dropped", "ip", d.IP)
		}
	}
	if cfg.Web.Listen != "" {
		if ab, err = autoban.Open(filepath.Join(cfg.Web.DataDir, "autoban.json")); err != nil {
			return fmt.Errorf("autoban: %w", err)
		}
		p.Tap = func(ev safeline.Event) { queue(ab.Process(web.HitOf(ev))) }
	}
	go p.Run(ctx, events)

	var maxInterval time.Duration
	for i, in := range cfg.Instances {
		c := &collector.Collector{
			ID: in.ID, Name: in.Name, Src: clients[i], State: store, Stats: st, Log: log,
			Interval: in.PollInterval.D(), Lookback: in.Lookback.D(), PageSize: in.PageSize, MaxPages: in.MaxPages, Backfill: in.Backfill,
		}
		st.Instance(in.ID, func(*stats.Instance) {})
		maxInterval = max(maxInterval, in.PollInterval.D())
		go c.Run(ctx, events)
	}

	tracking := map[string]*analytics.Collector{}
	var geo *analytics.Geo
	if cfg.Analytics.GeoIPDB != "" {
		if geo, err = analytics.OpenGeo(cfg.Analytics.GeoIPDB); err != nil {
			log.Warn("analytics: no geo database, countries stay unknown", "err", err)
		}
	}
	for i, in := range cfg.Instances {
		if in.Logs.AccessDir == "" {
			continue
		}
		a := &analytics.Collector{
			AccessDir: in.Logs.AccessDir, ErrorLog: in.Logs.ErrorLog, Geo: geo, Log: log,
			Store:    &analytics.Store{Dir: filepath.Join(cfg.Web.DataDir, "analytics", in.ID), Retention: cfg.Analytics.Retention.D()},
			SiteOf:   siteResolver(ctx, clients[i]),
			Backfill: *cfg.Analytics.Backfill,
		}
		if ab != nil {
			id := in.ID
			a.OnAccess = func(x analytics.Access, cl analytics.Client) { queue(ab.Access(web.RequestOf(id, x, cl))) }
		}
		tracking[in.ID] = a
		go a.Run(ctx)
	}

	if cfg.HTTP.Listen != "" {
		go serveHTTP(ctx, cfg.HTTP.Listen, st, 3*maxInterval+time.Minute, log)
	}

	webErr := make(chan error, 1)
	if cfg.Web.Listen != "" {
		ws := &web.Server{Cfg: cfg, Clients: clients, Senders: senders, Stats: st, History: hist,
			Rules: p, Log: log, Version: version, RuleFile: ruleFile, Analytics: tracking, Geo: geo,
			Autoban: ab, Decisions: decisions, DryRun: dryRun}
		if err := ws.Open(activeRules); err != nil {
			return fmt.Errorf("web: %w", err)
		}
		if !dryRun {
			ws.StartExpiry(ctx)
		}
		ws.StartAutoban(ctx)
		go func() { webErr <- ws.ListenAndServe(ctx) }()
	}

	log.Info("started", "version", version, "instances", len(cfg.Instances), "rules", len(activeRules), "channels", len(cfg.Channels), "siem", len(cfg.SIEM), "web", cfg.Web.Listen, "dry_run", dryRun)
	select {
	case <-ctx.Done():
	case err := <-webErr:
		if err != nil {
			return fmt.Errorf("web: %w", err)
		}
	}
	log.Info("stopping")
	return nil
}

// siteResolver maps a server_name from tengine's error log to the id of
// the SafeLine site, re-reading the sites every ten minutes.
func siteResolver(ctx context.Context, c *safeline.Client) func(string) string {
	var mu sync.Mutex
	var names map[string]string
	var at time.Time
	return func(server string) string {
		mu.Lock()
		defer mu.Unlock()
		if time.Since(at) > 10*time.Minute {
			at = time.Now()
			cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			sites, err := c.Sites(cctx)
			cancel()
			if err == nil {
				names = map[string]string{}
				for _, s := range sites {
					for _, n := range s.ServerNames {
						names[strings.ToLower(n)] = strconv.Itoa(s.ID)
					}
				}
			}
		}
		server = strings.ToLower(server)
		if id, ok := names[server]; ok {
			return id
		}
		for n, id := range names {
			if strings.HasPrefix(n, "*.") && strings.HasSuffix(server, n[1:]) {
				return id
			}
		}
		return ""
	}
}

func runCheck(ctx context.Context, clients []*safeline.Client) error {
	var failed bool
	for _, c := range clients {
		rows, err := c.ListRecords(ctx, 0, 1, 5)
		if err != nil {
			fmt.Printf("%-20s FAIL %v\n", c.ID, err)
			failed = true
			continue
		}
		fmt.Printf("%-20s OK   %d records on the first page\n", c.ID, len(rows))
		for _, r := range rows {
			fmt.Printf("    %s %s %s %s%s [%s] %s risk=%d\n", r.EventID, r.Time.Format(time.DateTime), r.SrcIP, r.Host, r.URLPath,
				safeline.AttackTypeCode(r.AttackType), r.ActionName(), r.RiskLevel)
		}
	}
	if failed {
		return errors.New("some instances are not reachable")
	}
	return nil
}

func runTestChannel(ctx context.Context, cfg *config.Config, name string, hc *http.Client) error {
	for _, ch := range cfg.Channels {
		if ch.Name != name {
			continue
		}
		s, err := notify.NewSender(ch, hc)
		if err != nil {
			return err
		}
		now := time.Now()
		ev := safeline.Event{Instance: cfg.Instances[0].ID, InstanceName: cfg.Instances[0].Name, Record: safeline.Record{
			EventID: "test", SrcIP: "203.0.113.10", Host: "example.com", URLPath: "/login?id=1'+or+1=1--",
			AttackType: 0, Action: safeline.ActionDeny, Country: "Test", Time: now,
		}}
		a := rules.Alert{
			Rule: "test", Severity: "info", GroupBy: "src_ip", GroupKey: ev.SrcIP, Count: 1,
			First: now, Last: now, Denied: 1, Hosts: []string{ev.Host}, Types: []int{0}, Samples: []safeline.Event{ev},
		}
		if err := s.Send(ctx, a); err != nil {
			return err
		}
		fmt.Println("test alert sent to", name)
		return nil
	}
	return fmt.Errorf("no channel named %q", name)
}

func serveHTTP(ctx context.Context, addr string, st *stats.Registry, maxAge time.Duration, log *slog.Logger) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if !st.Healthy(maxAge) {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		st.WriteJSON(w)
	})
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		st.WritePrometheus(w)
	})
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		srv.Close()
	}()
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("http server", "err", err)
	}
}

// loadRules prefers the rules saved in the panel over the config file.
func loadRules(cfg *config.Config, file string) ([]config.Rule, error) {
	b, err := os.ReadFile(file)
	if os.IsNotExist(err) {
		return cfg.Rules, nil
	}
	if err != nil {
		return nil, err
	}
	var rs []config.Rule
	if err := yaml.Unmarshal(b, &rs); err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	if err := cfg.ValidateRules(rs); err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	return rs, nil
}

func runResetPassword(cfgPath, name string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	users, err := auth.OpenUsers(filepath.Join(cfg.Web.DataDir, "users.json"))
	if err != nil {
		return err
	}
	pw := auth.RandomPassword()
	if err := users.SetPassword(name, pw); err != nil {
		return err
	}
	fmt.Printf("new password for %s: %s\n", name, pw)
	return nil
}
