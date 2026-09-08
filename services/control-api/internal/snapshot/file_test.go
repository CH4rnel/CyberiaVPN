//go:build linux

package snapshot_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/CH4rnel/CyberiaVPN/services/control-api/internal/snapshot"
)

func TestSnapshotPersistenceAndExclusiveOwnership(t *testing.T) {
	path := filepath.Join(privateDir(t), "state.json")
	file, err := snapshot.Open(path, 64)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := file.Read(); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("new snapshot: %v", err)
	}
	if other, err := snapshot.Open(path, 64); !errors.Is(err, snapshot.ErrLocked) {
		if other != nil {
			other.Close()
		}
		t.Fatalf("second owner: %v", err)
	}
	if err := file.Write([]byte(`{"version":1}`)); err != nil {
		t.Fatal(err)
	}
	if err := file.Write(make([]byte, 65)); err == nil {
		t.Fatal("accepted oversized snapshot")
	}
	data, err := file.Read()
	if err != nil || string(data) != `{"version":1}` {
		t.Fatalf("old snapshot lost: %s %v", data, err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("private mode: %v %v", info, err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Write([]byte(`{}`)); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("write after close: %v", err)
	}
	reopened, err := snapshot.Open(path, 64)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	data, err = reopened.Read()
	if err != nil || string(data) != `{"version":1}` {
		t.Fatalf("restart lost snapshot: %s %v", data, err)
	}
}

func TestSnapshotRejectsUnsafeFilesAndBoundsReads(t *testing.T) {
	for _, kind := range []string{"symlink", "public", "oversized", "directory"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(privateDir(t), "state.json")
			switch kind {
			case "symlink":
				if err := os.Symlink("missing", path); err != nil {
					t.Fatal(err)
				}
			case "public":
				if err := os.WriteFile(path, []byte(`{}`), 0644); err != nil {
					t.Fatal(err)
				}
			case "oversized":
				if err := os.WriteFile(path, make([]byte, 65), 0600); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			}
			file, err := snapshot.Open(path, 64)
			if err != nil {
				return
			}
			defer file.Close()
			if _, err := file.Read(); err == nil {
				t.Fatal("accepted unsafe snapshot")
			}
		})
	}
}

func TestSnapshotWriteFailurePreservesCommittedData(t *testing.T) {
	dir := privateDir(t)
	file, err := snapshot.Open(filepath.Join(dir, "state.json"), 64)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := file.Write([]byte("old")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0700)
	if err := file.Write([]byte("new")); err == nil {
		if os.Geteuid() == 0 {
			t.Skip("root bypasses permissions")
		}
		t.Fatal("write unexpectedly succeeded")
	}
	data, err := file.Read()
	if err != nil || string(data) != "old" {
		t.Fatalf("committed data changed: %s %v", data, err)
	}
}

func TestDecodeRejectsUnknownAndTrailingData(t *testing.T) {
	for _, data := range []string{`{"unknown":1}`, `{} {}`, `{`, `null`} {
		var value struct {
			Version int `json:"version"`
		}
		if err := snapshot.Decode([]byte(data), &value); err == nil {
			t.Fatalf("accepted %s", data)
		}
	}
}

func privateDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}
