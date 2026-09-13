//go:build linux

package configuration_test

import (
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/CH4rnel/CyberiaVPN/services/control-api/internal/configuration"
)

func TestClientStatePersistsAcceptanceBeforeApplying(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	signer, err := configuration.NewEd25519Signer("key", private)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := configuration.NewEd25519Verifier(map[string]ed25519.PublicKey{"key": private.Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	state, err := configuration.OpenClientState(filepath.Join(dir, "client.json"), "laptop-1")
	if err != nil {
		t.Fatal(err)
	}
	config := validConfig(testNow())
	config.Version = 2
	envelope, err := configuration.Seal(config, testNow(), signer)
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := state.Accept(envelope, testNow(), verifier)
	if err != nil || accepted.Version != 2 || state.Version() != 2 {
		t.Fatalf("accept=%+v err=%v", accepted, err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	state, err = configuration.OpenClientState(filepath.Join(dir, "client.json"), "laptop-1")
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	if state.Version() != 2 {
		t.Fatalf("lost version %d", state.Version())
	}
	if _, err := state.Accept(envelope, testNow(), verifier); !errors.Is(err, configuration.ErrStaleVersion) {
		t.Fatalf("replay=%v", err)
	}
	if other, err := configuration.OpenClientState(filepath.Join(dir, "client.json"), "phone"); err == nil {
		other.Close()
		t.Fatal("allowed a different device")
	}
}
