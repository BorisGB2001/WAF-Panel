package analytics

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
)

// Collector follows SafeLine's logs on this host into a Store.
type Collector struct {
	// AccessDir holds accesslog_<site id> and its rotated copies
	// accesslog_<site id>_<date>.
	AccessDir string
	// ErrorLog is tengine's error log; empty skips upstream errors.
	ErrorLog string
	Store    *Store
	Geo      *Geo
	// SiteOf maps a server_name from the error log to a site id.
	SiteOf func(server string) string
	// Backfill reads rotated logs on the first start.
	Backfill bool
	Log      *slog.Logger
	// OnAccess sees every access line read, old ones from a backfill too;
	// it must not block.
	OnAccess func(Access, Client)

	mu      sync.Mutex
	cursors map[string]*Cursor
	status  Status
	// uas caches ParseUA: a site sees few distinct User-Agents, and the
	// bot pattern is the most expensive step of a line.
	uas map[string]Client
}

func (c *Collector) client(ua string) Client {
	c.mu.Lock()
	defer c.mu.Unlock()
	if cl, ok := c.uas[ua]; ok {
		return cl
	}
	if c.uas == nil || len(c.uas) > 50_000 {
		c.uas = map[string]Client{}
	}
	cl := ParseUA(ua)
	c.uas[ua] = cl
	return cl
}

// Status tells the panel what is being collected.
type Status struct {
	Sites     []string  // site ids with an access log
	LastRead  time.Time // last pass that read something
	Lines     int64     // access lines since start
	Skipped   int64     // lines that did not parse
	ErrLines  int64     // upstream errors since start
	LastError string
	Geo       bool
}

var currentRe = regexp.MustCompile(`^accesslog_(\d+)$`)
var rotatedRe = regexp.MustCompile(`^accesslog_(\d+)_\d`)

func (c *Collector) cursorFile() string { return filepath.Join(c.Store.Dir, "cursors.json") }

func (c *Collector) loadCursors() bool {
	c.cursors = map[string]*Cursor{}
	b, err := os.ReadFile(c.cursorFile())
	if err != nil {
		return false
	}
	return json.Unmarshal(b, &c.cursors) == nil
}

func (c *Collector) saveCursors() error {
	b, _ := json.Marshal(c.cursors)
	tmp := c.cursorFile() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, c.cursorFile())
}

func (c *Collector) Status() Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	st := c.status
	st.Sites = slices.Clone(st.Sites)
	return st
}

func (c *Collector) access(site string) func(string) {
	return func(line string) {
		a, err := ParseAccess(line)
		c.mu.Lock()
		if err != nil {
			c.status.Skipped++
			c.mu.Unlock()
			return
		}
		c.status.Lines++
		c.mu.Unlock()
		cl := c.client(a.UA)
		c.Store.AddAccess(site, a, c.Geo.Lookup(a.IP), cl)
		if c.OnAccess != nil {
			c.OnAccess(a, cl)
		}
	}
}

func (c *Collector) errors(line string) {
	e, ok := ParseError(line)
	if !ok {
		return
	}
	site := "0"
	if c.SiteOf != nil {
		if id := c.SiteOf(e.Server); id != "" {
			site = id
		}
	}
	c.mu.Lock()
	c.status.ErrLines++
	c.mu.Unlock()
	c.Store.AddError(site, e)
}

// backfill reads the rotated access logs, oldest first, before the
// current ones are followed from their start.
func (c *Collector) backfill() {
	es, err := os.ReadDir(c.AccessDir)
	if err != nil {
		return
	}
	var names []string
	for _, e := range es {
		if rotatedRe.MatchString(e.Name()) && !strings.HasSuffix(e.Name(), ".gz") {
			names = append(names, e.Name())
		}
	}
	slices.Sort(names) // the date in the name sorts by time
	for _, n := range names {
		site := rotatedRe.FindStringSubmatch(n)[1]
		c.Log.Info("analytics backfill", "file", n)
		readAll(filepath.Join(c.AccessDir, n), c.access(site))
	}
}

// pass reads what was added to every log since the last pass.
func (c *Collector) pass() {
	before := c.Status().Lines + c.Status().ErrLines
	var sites []string
	var errs []string
	if es, err := os.ReadDir(c.AccessDir); err != nil {
		errs = append(errs, err.Error())
	} else {
		for _, e := range es {
			m := currentRe.FindStringSubmatch(e.Name())
			if m == nil {
				continue
			}
			sites = append(sites, m[1])
			key := "access:" + m[1]
			if c.cursors[key] == nil {
				c.cursors[key] = &Cursor{}
			}
			if err := follow(filepath.Join(c.AccessDir, e.Name()), c.cursors[key], c.access(m[1])); err != nil {
				errs = append(errs, err.Error())
			}
		}
	}
	if c.ErrorLog != "" {
		if c.cursors["error"] == nil {
			// The error log is not rotated by SafeLine and may be large:
			// start a new installation from its end.
			c.cursors["error"] = &Cursor{}
			if fi, err := os.Stat(c.ErrorLog); err == nil && !c.Backfill {
				c.cursors["error"] = &Cursor{Ino: inode(fi), Off: fi.Size()}
			}
		}
		if err := follow(c.ErrorLog, c.cursors["error"], c.errors); err != nil {
			errs = append(errs, err.Error())
		}
	}
	c.mu.Lock()
	c.status.Sites = sites
	c.status.LastError = strings.Join(errs, "; ")
	if c.status.Lines+c.status.ErrLines > before {
		c.status.LastRead = time.Now()
	}
	c.mu.Unlock()
}

// Run collects until ctx ends.
func (c *Collector) Run(ctx context.Context) {
	if err := c.Store.Load(); err != nil {
		c.Log.Warn("analytics: loading stored days", "err", err)
	}
	c.status.Geo = c.Geo != nil
	if !c.loadCursors() && c.Backfill {
		c.backfill()
	}
	flush := func() {
		if err := c.Store.Flush(); err != nil {
			c.Log.Error("analytics: saving", "err", err)
			return
		}
		// Cursors after the data, so a crash repeats lines, never loses them.
		if err := c.saveCursors(); err != nil {
			c.Log.Error("analytics: saving cursors", "err", err)
		}
	}
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	last := time.Now()
	for {
		c.pass()
		if time.Since(last) >= time.Minute {
			flush()
			last = time.Now()
		}
		select {
		case <-ctx.Done():
			flush()
			return
		case <-tick.C:
		}
	}
}
