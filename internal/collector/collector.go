// Package collector polls one SafeLine instance for new attack records.
package collector

import (
	"context"
	"log/slog"
	"maps"
	"slices"
	"time"

	"wafpanel/internal/safeline"
	"wafpanel/internal/state"
	"wafpanel/internal/stats"
)

// Source is the part of safeline.Client the collector needs.
type Source interface {
	ListRecords(ctx context.Context, since int64, page, size int) ([]safeline.Record, error)
}

type Collector struct {
	ID       string
	Name     string
	Src      Source
	State    *state.Store
	Stats    *stats.Registry
	Log      *slog.Logger
	Interval time.Duration
	// Lookback is how far behind the newest record every poll re-reads.
	// Records reach the API up to tens of seconds after their timestamp,
	// so a late one lands behind records that were already seen.
	Lookback time.Duration
	PageSize int
	MaxPages int
	Backfill bool
	// now is replaceable in tests.
	now func() time.Time
}

// Run polls until ctx is done and sends new events to out, oldest first.
func (c *Collector) Run(ctx context.Context, out chan<- safeline.Event) {
	t := time.NewTicker(c.Interval)
	defer t.Stop()
	for {
		if err := c.Poll(ctx, out); err != nil && ctx.Err() == nil {
			c.Log.Warn("poll failed", "instance", c.ID, "err", err)
			c.Stats.Instance(c.ID, func(s *stats.Instance) { s.PollErrors++; s.LastError = err.Error() })
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Poll reads every record of the lookback window and emits the ones whose
// event_id has not been seen yet.
func (c *Collector) Poll(ctx context.Context, out chan<- safeline.Event) error {
	now := time.Now()
	if c.now != nil {
		now = c.now()
	}
	c.Stats.Instance(c.ID, func(s *stats.Instance) { s.LastPoll = now })

	cur, known := c.State.Cursor(c.ID)
	if cur.Seen == nil {
		cur.Seen = map[string]int64{}
	}
	lookback := c.Lookback.Milliseconds()
	var since int64
	switch {
	case known:
		since = cur.Since - lookback
	case c.Backfill:
		since = 0
	default:
		// First start: remember the current window without emitting it.
		since = now.UnixMilli() - lookback
		cur.Since = now.UnixMilli()
	}

	var fresh []safeline.Record
	complete := false
	for page := 1; page <= c.MaxPages; page++ {
		rows, err := c.Src.ListRecords(ctx, max(since, 0), page, c.PageSize)
		if err != nil {
			return err
		}
		for _, r := range rows {
			if r.EventID == "" {
				continue
			}
			if _, ok := cur.Seen[r.EventID]; !ok {
				fresh = append(fresh, r)
			}
		}
		if len(rows) < c.PageSize {
			complete = true
			break
		}
	}
	if !complete {
		c.Log.Warn("window has more records than max_pages*page_size, older ones are skipped",
			"instance", c.ID, "fetched", len(fresh))
		c.Stats.Instance(c.ID, func(s *stats.Instance) { s.Skipped++ })
	}

	emit := known || c.Backfill
	// Oldest first, so threshold windows and SIEM see the real order.
	slices.SortStableFunc(fresh, func(a, b safeline.Record) int { return a.Time.Compare(b.Time) })
	for _, r := range fresh {
		if emit {
			select {
			case out <- safeline.Event{Instance: c.ID, InstanceName: c.Name, Record: r}:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		ts := r.Time.UnixMilli()
		cur.Seen[r.EventID] = ts
		cur.Since = max(cur.Since, ts)
	}
	if !emit {
		c.Log.Info("first start, skipping existing records", "instance", c.ID, "records", len(fresh))
	}

	// Ids older than the window cannot come back in a response.
	maps.DeleteFunc(cur.Seen, func(_ string, ts int64) bool { return ts < cur.Since-lookback })

	if err := c.State.SetCursor(c.ID, cur); err != nil {
		return err
	}
	n := 0
	if emit {
		n = len(fresh)
	}
	c.Stats.Instance(c.ID, func(s *stats.Instance) {
		s.LastOK = now
		s.LastError = ""
		s.Cursor = cur.Since
		s.Events += int64(n)
	})
	return nil
}
