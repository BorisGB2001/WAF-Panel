package analytics

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// Cursor is how far a log has been read: the file is identified by its
// inode, so a rename by log rotation is noticed.
type Cursor struct {
	Ino uint64 `json:"ino"`
	Off int64  `json:"off"`
}

func inode(fi os.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Ino)
	}
	return 0
}

// maxRead bounds one pass over a file, so a large backlog is read over
// several ticks and never holds the store for long.
const maxRead = 32 << 20

// follow reads the new complete lines of path and calls fn for each.
// When path was rotated since the last pass, the rest of the old file is
// read first from wherever rotation left it in the same directory.
func follow(path string, c *Cursor, fn func(string)) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	ino := inode(fi)
	if c.Ino != 0 && c.Ino != ino {
		if old := findInode(filepath.Dir(path), c.Ino); old != "" {
			for {
				n, err := readLines(old, c.Off, fn)
				c.Off += n
				if err != nil || n == 0 {
					break
				}
			}
		}
		c.Ino, c.Off = ino, 0
	}
	if c.Ino == 0 {
		c.Ino = ino
	}
	if fi.Size() < c.Off { // truncated in place
		c.Off = 0
	}
	n, err := readLines(path, c.Off, fn)
	c.Off += n
	return err
}

func findInode(dir string, ino uint64) string {
	es, _ := os.ReadDir(dir)
	for _, e := range es {
		if fi, err := e.Info(); err == nil && inode(fi) == ino {
			return filepath.Join(dir, e.Name())
		}
	}
	return ""
}

// readLines calls fn for each complete line from off and returns the
// bytes consumed; a trailing partial line is left for the next pass.
func readLines(path string, off int64, fn func(string)) (int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return 0, err
	}
	r := bufio.NewReaderSize(f, 256<<10)
	var n int64
	for n < maxRead {
		line, err := r.ReadString('\n')
		if err != nil { // EOF: an unfinished line stays unread
			if err == io.EOF {
				return n, nil
			}
			return n, err
		}
		n += int64(len(line))
		fn(line[:len(line)-1])
	}
	return n, nil
}

// readAll reads a whole rotated file, in maxRead steps.
func readAll(path string, fn func(string)) {
	var off int64
	for {
		n, err := readLines(path, off, fn)
		off += n
		if err != nil || n == 0 {
			return
		}
	}
}
