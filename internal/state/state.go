// Package state persists what each collector has already processed.
package state

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
)

// Cursor is the progress of one instance. SafeLine records have no
// sequential id, so progress is the newest record time plus the event ids
// already seen in the lookback window that is re-read on every poll.
type Cursor struct {
	// Since is the newest record time seen, Unix milliseconds.
	Since int64 `json:"since"`
	// Seen maps event_id to its record time (Unix milliseconds).
	Seen map[string]int64 `json:"seen"`
}

type Store struct {
	path    string
	mu      sync.Mutex
	cursors map[string]Cursor
}

func Open(path string) (*Store, error) {
	s := &Store{path: path, cursors: map[string]Cursor{}}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &s.cursors); err != nil {
		// A state file of the old id-based format is not usable; start over.
		s.cursors = map[string]Cursor{}
	}
	return s, nil
}

func (s *Store) Cursor(instance string) (Cursor, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.cursors[instance]
	return c, ok
}

// SetCursor records the cursor and writes the file atomically.
func (s *Store) SetCursor(instance string, c Cursor) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cursors[instance] = c
	b, err := json.Marshal(s.cursors)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".state-*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), s.path)
}
