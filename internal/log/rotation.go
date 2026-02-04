package log

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// RotatingFile is a io.WriteCloser that writes to a file and rotates it when it reaches a certain size.
type RotatingFile struct {
	mu sync.Mutex

	path       string
	maxSize    int64 // bytes
	maxBackups int

	file *os.File
	size int64
}

// NewRotatingFile creates a new RotatingFile.
// maxSize uses bytes. maxBackups is the number of old log files to keep.
func NewRotatingFile(path string, maxSize int64, maxBackups int) (*RotatingFile, error) {
	rf := &RotatingFile{
		path:       path,
		maxSize:    maxSize,
		maxBackups: maxBackups,
	}

	if err := rf.open(); err != nil {
		return nil, err
	}

	return rf, nil
}

func (rf *RotatingFile) open() error {
	// Ensure directory exists
	dir := filepath.Dir(rf.path)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("failed to create log directory: %w", err)
	}

	// Open file (0600 security: only owner can read/write)
	f, err := os.OpenFile(rf.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}

	info, err := f.Stat()
	if err != nil {
		_ = f.Close() // Best-effort close on stat failure
		return fmt.Errorf("failed to stat log file: %w", err)
	}

	rf.file = f
	rf.size = info.Size()
	return nil
}

// Write implements io.Writer. It writes p to the file, rotating if necessary.
func (rf *RotatingFile) Write(p []byte) (n int, err error) {
	rf.mu.Lock()
	defer rf.mu.Unlock()

	writeLen := int64(len(p))

	if rf.size+writeLen > rf.maxSize {
		if err := rf.rotate(); err != nil {
			return 0, fmt.Errorf("failed to rotate log: %w", err)
		}
	}

	n, err = rf.file.Write(p)
	rf.size += int64(n)
	return n, err
}

// rotate closes the current file, performs rotation, and opens a new file.
// Must be called with mu locked.
func (rf *RotatingFile) rotate() error {
	if rf.file != nil {
		if err := rf.file.Close(); err != nil {
			return err
		}
		rf.file = nil
	}

	// Rotate backups
	// Example: maxBackups=3
	// log.3 -> deleted
	// log.2 -> log.3
	// log.1 -> log.2
	// log   -> log.1

	// Delete oldest backup if it exists
	lastBackup := fmt.Sprintf("%s.%d", rf.path, rf.maxBackups)
	if _, err := os.Stat(lastBackup); err == nil {
		if err := os.Remove(lastBackup); err != nil {
			return fmt.Errorf("failed to remove old backup: %w", err)
		}
	}

	// Shift existing backups
	for i := rf.maxBackups - 1; i >= 1; i-- {
		oldPath := fmt.Sprintf("%s.%d", rf.path, i)
		newPath := fmt.Sprintf("%s.%d", rf.path, i+1)

		if _, err := os.Stat(oldPath); err == nil {
			if err := os.Rename(oldPath, newPath); err != nil {
				return fmt.Errorf("failed to rename backup: %w", err)
			}
		}
	}

	// Rename current log to .1
	firstBackup := fmt.Sprintf("%s.1", rf.path)
	if _, err := os.Stat(rf.path); err == nil {
		if err := os.Rename(rf.path, firstBackup); err != nil {
			return fmt.Errorf("failed to rotate current log: %w", err)
		}
	}

	// Open new file
	return rf.open()
}

// Close implements io.Closer.
func (rf *RotatingFile) Close() error {
	rf.mu.Lock()
	defer rf.mu.Unlock()

	if rf.file == nil {
		return nil
	}

	err := rf.file.Close()
	rf.file = nil
	return err
}
