package collector

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"wafpanel/internal/safeline"
	"wafpanel/internal/state"
	"wafpanel/internal/stats"
)

var t0 = time.Date(2026, 10, 30, 10, 0, 0, 0, time.UTC)

// fakeSource behaves like /api/open/records: start filters by timestamp
// (inclusive, milliseconds) and rows come newest first.
type fakeSource struct{ recs []safeline.Record }

func (f *fakeSource) add(id string, sec int) {
	f.recs = append(f.recs, safeline.Record{EventID: id, Time: t0.Add(time.Duration(sec) * time.Second)})
}

func (f *fakeSource) ListRecords(_ context.Context, since int64, page, size int) ([]safeline.Record, error) {
	var all []safeline.Record
	for _, r := range f.recs {
		if r.Time.UnixMilli() >= since {
			all = append(all, r)
		}
	}
	slices.SortStableFunc(all, func(a, b safeline.Record) int { return b.Time.Compare(a.Time) })
	lo, hi := min((page-1)*size, len(all)), min(page*size, len(all))
	return all[lo:hi], nil
}

func newCollector(t *testing.T, src Source, backfill bool, clock *time.Time) *Collector {
	t.Helper()
	st, err := state.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	return &Collector{
		ID: "a", Name: "A", Src: src, State: st, Stats: stats.New(),
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Interval: time.Second,
		Lookback: time.Minute, PageSize: 3, MaxPages: 5, Backfill: backfill,
		now: func() time.Time { return *clock },
	}
}

func poll(t *testing.T, c *Collector) []string {
	t.Helper()
	ch := make(chan safeline.Event, 100)
	if err := c.Poll(context.Background(), ch); err != nil {
		t.Fatal(err)
	}
	close(ch)
	var ids []string
	for ev := range ch {
		ids = append(ids, ev.EventID)
	}
	return ids
}

func TestFirstStartSkipsExisting(t *testing.T) {
	clock := t0.Add(10 * time.Second)
	src := &fakeSource{}
	src.add("a", 1)
	src.add("b", 2)
	c := newCollector(t, src, false, &clock)

	if got := poll(t, c); len(got) != 0 {
		t.Fatalf("first poll emitted %v", got)
	}
	src.add("c", 20)
	src.add("d", 21)
	if got := poll(t, c); !slices.Equal(got, []string{"c", "d"}) {
		t.Fatalf("got %v, want c d", got)
	}
	if got := poll(t, c); len(got) != 0 {
		t.Fatalf("repeat poll emitted %v", got)
	}
}

func TestLateRecordIsCaught(t *testing.T) {
	clock := t0
	src := &fakeSource{}
	c := newCollector(t, src, false, &clock)
	poll(t, c)
	src.add("x", 10)
	src.add("y", 30)
	if got := poll(t, c); !slices.Equal(got, []string{"x", "y"}) {
		t.Fatalf("got %v", got)
	}
	// Arrives after y was seen but carries an older timestamp.
	src.add("late", 25)
	if got := poll(t, c); !slices.Equal(got, []string{"late"}) {
		t.Fatalf("late record: got %v", got)
	}
}

func TestBackfillAcrossPages(t *testing.T) {
	clock := t0
	src := &fakeSource{}
	for i, id := range []string{"1", "2", "3", "4", "5", "6", "7"} {
		src.add(id, i)
	}
	c := newCollector(t, src, true, &clock)
	if got := poll(t, c); !slices.Equal(got, []string{"1", "2", "3", "4", "5", "6", "7"}) {
		t.Fatalf("got %v", got)
	}
}

func TestSameSecondRecordsAreAllEmitted(t *testing.T) {
	clock := t0
	src := &fakeSource{}
	c := newCollector(t, src, false, &clock)
	poll(t, c)
	for _, id := range []string{"p", "q", "r", "s"} {
		src.add(id, 5)
	}
	if got := poll(t, c); len(got) != 4 {
		t.Fatalf("got %v", got)
	}
	src.add("t", 5)
	if got := poll(t, c); !slices.Equal(got, []string{"t"}) {
		t.Fatalf("got %v", got)
	}
}

func TestSeenIsPruned(t *testing.T) {
	clock := t0
	src := &fakeSource{}
	c := newCollector(t, src, false, &clock)
	poll(t, c)
	src.add("old", 1)
	poll(t, c)
	src.add("new", 600)
	poll(t, c)
	cur, _ := c.State.Cursor("a")
	if _, ok := cur.Seen["old"]; ok || len(cur.Seen) != 1 {
		t.Fatalf("seen not pruned: %v", cur.Seen)
	}
}
