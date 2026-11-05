package web

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"wafpanel/internal/analytics"
)

func TestTrafficFromLogs(t *testing.T) {
	ts, s, _ := newTestServerWith(t, newSiteFake())
	c := browser(ts)
	pw, _ := os.ReadFile(filepath.Join(s.Cfg.Web.DataDir, "initial-admin-password"))
	login(t, ts, c, "admin", strings.TrimSpace(string(pw)))

	// Without logs the page keeps SafeLine's own blocks.
	if _, page := get(t, ts, c, "/stats"); strings.Contains(page, "Traffic from logs") || !strings.Contains(page, "set logs.access_dir") {
		t.Fatal("analytics shown without logs")
	}

	logs := t.TempDir()
	now := time.Now()
	var b strings.Builder
	for i := 0; i < 50; i++ {
		status := 200
		if i%10 == 0 {
			status = 501
		}
		fmt.Fprintf(&b, `10.0.22.15 | - | %s | "im.example.ru" | "GET /api/v4/users/%026d/status HTTP/1.1" | %d | 120 | "-" | "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.7339.249 Electron/38.7.2 Safari/537.36 Mattermost/6.0.4"`+"\n",
			now.Format("02/Jan/2006:15:04:05 -0700"), i, status)
	}
	os.WriteFile(filepath.Join(logs, "accesslog_4"), []byte(b.String()), 0o644)
	col := &analytics.Collector{AccessDir: logs, Log: slog.New(slog.DiscardHandler),
		Store: &analytics.Store{Dir: t.TempDir(), Retention: 90 * 24 * time.Hour}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { col.Run(ctx); close(done) }()
	// The collector saves on its way out; let it finish before the
	// temporary directories go.
	defer func() { cancel(); <-done }()
	for i := 0; col.Status().Lines < 50 && i < 100; i++ {
		time.Sleep(20 * time.Millisecond)
	}
	s.Analytics = map[string]*analytics.Collector{"prod": col}

	for _, period := range []string{"24h", "7d", "30d"} {
		code, page := get(t, ts, c, "/stats?period="+period)
		for _, want := range []string{"Traffic from logs", "Mattermost Desktop", "GET /api/v4/users/:id/status", "Not Implemented",
			"10.0.22.15", "come from 10.0.22.15, a private address"} {
			if code != 200 || !strings.Contains(page, want) {
				t.Errorf("%s: %d, no %q", period, code, want)
			}
		}
	}
	// A site filter for a site without data shows no requests from others.
	if _, page := get(t, ts, c, "/stats?site=2"); strings.Contains(page, "GET /api/v4/users/:id/status") {
		t.Error("site filter ignored")
	}
}
