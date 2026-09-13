//go:build linux

package configuration_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/CH4rnel/CyberiaVPN/services/control-api/internal/configuration"
)

func TestFileStoreSurvivesRestartAndRejectsRollback(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "configs.json")
	store, err := configuration.OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Publish(testEnvelope("device", 1)); err != nil {
		t.Fatal(err)
	}
	if err := store.Publish(testEnvelope("device", 2)); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = configuration.OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	got, err := store.Latest("device")
	if err != nil || got.Config.Version != 2 {
		t.Fatalf("restored=%+v err=%v", got, err)
	}
	if err := store.Publish(testEnvelope("device", 1)); !errors.Is(err, configuration.ErrStaleVersion) {
		t.Fatalf("rollback=%v", err)
	}
}
