// Package snapshot provides bounded, private, atomically replaced local state.
// The containing directory and its ancestors must be owned by a trusted operator.
// Locks are advisory; all writers must use this package. Network filesystems and
// multi-host ownership are unsupported.
package snapshot

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

var ErrLocked = errors.New("snapshot already owned by another store")

// File owns an exclusive process lock until Close. Never copy it after use.
type File struct {
	mu     sync.Mutex
	path   string
	limit  int64
	lock   *os.File
	failed error
}

func Open(path string, limit int64) (*File, error) {
	if path == "" || limit <= 0 || limit > 64<<20 {
		return nil, errors.New("snapshot path and size bound in (0, 64 MiB] required")
	}
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("snapshot directory must be private and must not be a symlink")
	}
	lockPath := path + ".lock"
	if err := checkPrivateFile(lockPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := lockFile(lock); err != nil {
		lock.Close()
		return nil, err
	}
	return &File{path: path, limit: limit, lock: lock}, nil
}

func checkPrivateFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return errors.New("snapshot must be a private regular file")
	}
	return nil
}

// Check rejects a closed store or an uncertain commit after a directory-sync
// failure. Such a store must be closed and reopened before further use.
func (file *File) Check() error {
	file.mu.Lock()
	defer file.mu.Unlock()
	return file.check()
}

func (file *File) check() error {
	if file.lock == nil {
		return os.ErrClosed
	}
	return file.failed
}

func (file *File) Read() ([]byte, error) {
	file.mu.Lock()
	defer file.mu.Unlock()
	if err := file.check(); err != nil {
		return nil, err
	}
	if err := checkPrivateFile(file.path); err != nil {
		return nil, err
	}
	input, err := os.Open(file.path)
	if err != nil {
		return nil, err
	}
	defer input.Close()
	data, err := io.ReadAll(io.LimitReader(input, file.limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > file.limit {
		return nil, errors.New("snapshot exceeds size limit")
	}
	return data, nil
}

// Write acknowledges only after syncing both the new file and its directory.
// Errors before rename leave the previous committed snapshot intact.
func (file *File) Write(data []byte) error {
	file.mu.Lock()
	defer file.mu.Unlock()
	if err := file.check(); err != nil {
		return err
	}
	if int64(len(data)) > file.limit {
		return errors.New("snapshot exceeds size limit")
	}
	dir, err := os.Open(filepath.Dir(file.path))
	if err != nil {
		return err
	}
	defer dir.Close()
	temporary, err := os.CreateTemp(filepath.Dir(file.path), ".cyberia-snapshot-*")
	if err != nil {
		return err
	}
	defer os.Remove(temporary.Name())
	defer temporary.Close()
	if _, err := temporary.Write(data); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporary.Name(), file.path); err != nil {
		return err
	}
	if err := dir.Sync(); err != nil {
		file.failed = fmt.Errorf("snapshot commit durability uncertain: %w", err)
		return file.failed
	}
	return nil
}

func (file *File) Close() error {
	file.mu.Lock()
	defer file.mu.Unlock()
	if file.lock == nil {
		return nil
	}
	err := file.lock.Close()
	file.lock = nil
	return err
}

// Decode rejects unknown fields, null and trailing JSON values.
func Decode(data []byte, value any) error {
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return errors.New("null snapshot")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("trailing snapshot data")
	}
	return nil
}
