//go:build linux

package identity_test

import (
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/CH4rnel/CyberiaVPN/services/control-api/internal/identity"
)

func TestDurableEnrollmentSurvivesRestart(t *testing.T) {
	path := filepath.Join(privateStateDir(t), "enrollment.json")
	now := time.Unix(1800000000, 0)
	store, err := identity.OpenFileEnrollmentStore(path, time.Minute, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	challenge, err := store.Issue("account", "device", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = identity.OpenFileEnrollmentStore(path, time.Minute, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	request := identity.EnrollmentRequest{AccountID: "account", DeviceID: "device", PublicKey: private.Public().(ed25519.PublicKey), Challenge: challenge.Value}
	request.Signature = ed25519.Sign(private, request.SigningMessage())
	var successes atomic.Int32
	var workers sync.WaitGroup
	for range 8 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			if _, err := store.Enroll(request, now); err == nil {
				successes.Add(1)
			} else if !errors.Is(err, identity.ErrDeviceExists) {
				t.Errorf("enroll: %v", err)
			}
		}()
	}
	workers.Wait()
	if successes.Load() != 1 {
		t.Fatalf("successful registrations: %d", successes.Load())
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = identity.OpenFileEnrollmentStore(path, time.Minute, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	device, err := store.Device("account", "device")
	if err != nil || device.DeviceID != "device" {
		t.Fatalf("restored device: %+v %v", device, err)
	}
	device.PublicKey[0] ^= 1
	again, err := store.Device("account", "device")
	if err != nil || again.PublicKey[0] != request.PublicKey[0] {
		t.Fatal("mutable device snapshot")
	}
	if _, err := store.Device("other", "device"); !errors.Is(err, identity.ErrDeviceNotFound) {
		t.Fatalf("foreign lookup: %v", err)
	}
	if _, err := store.Enroll(request, now); !errors.Is(err, identity.ErrDeviceExists) {
		t.Fatalf("restart replay: %v", err)
	}
}

func TestDurableEnrollmentFailureAndCorruption(t *testing.T) {
	dir := privateStateDir(t)
	path := filepath.Join(dir, "enrollment.json")
	now := time.Unix(1800000000, 0)
	store, err := identity.OpenFileEnrollmentStore(path, time.Minute, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := os.Chmod(dir, 0500); err != nil {
		t.Fatal(err)
	}
	_, issueErr := store.Issue("account", "device", now)
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() != 0 {
		if issueErr == nil {
			t.Fatal("acknowledged unpersisted challenge")
		}
		if _, err := store.Issue("account", "device", now); err != nil {
			t.Fatalf("failed write consumed capacity: %v", err)
		}
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Issue("account", "other", now); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("closed store: %v", err)
	}
	if err := os.WriteFile(path, []byte(`{"schema":999}`), 0600); err != nil {
		t.Fatal(err)
	}
	if reopened, err := identity.OpenFileEnrollmentStore(path, time.Minute, 1); err == nil {
		reopened.Close()
		t.Fatal("reset corrupt state")
	}
}

func privateStateDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestFailedDurableEnrollmentDoesNotConsumeProof(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses permissions")
	}
	dir := privateStateDir(t)
	store, err := identity.OpenFileEnrollmentStore(filepath.Join(dir, "state.json"), time.Minute, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Unix(1800000000, 0)
	challenge, err := store.Issue("account", "device", now)
	if err != nil {
		t.Fatal(err)
	}
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	request := identity.EnrollmentRequest{AccountID: "account", DeviceID: "device", PublicKey: private.Public().(ed25519.PublicKey), Challenge: challenge.Value}
	request.Signature = ed25519.Sign(private, request.SigningMessage())
	if err := os.Chmod(dir, 0500); err != nil {
		t.Fatal(err)
	}
	_, enrollErr := store.Enroll(request, now)
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if enrollErr == nil {
		t.Fatal("acknowledged unpersisted registration")
	}
	if _, err := store.Device("account", "device"); !errors.Is(err, identity.ErrDeviceNotFound) {
		t.Fatalf("published failed registration: %v", err)
	}
	if _, err := store.Enroll(request, now); err != nil {
		t.Fatalf("proof consumed by failed write: %v", err)
	}
}

func TestExpiredDurableChallengeStaysConsumed(t *testing.T) {
	path := filepath.Join(privateStateDir(t), "state.json")
	store, err := identity.OpenFileEnrollmentStore(path, time.Minute, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Unix(1800000000, 0)
	challenge, err := store.Issue("account", "device", now)
	if err != nil {
		t.Fatal(err)
	}
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	request := identity.EnrollmentRequest{AccountID: "account", DeviceID: "device", PublicKey: private.Public().(ed25519.PublicKey), Challenge: challenge.Value}
	request.Signature = ed25519.Sign(private, request.SigningMessage())
	if _, err := store.Enroll(request, now.Add(time.Minute)); !errors.Is(err, identity.ErrInvalidChallenge) {
		t.Fatalf("accepted expired challenge: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = identity.OpenFileEnrollmentStore(path, time.Minute, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.Enroll(request, now); !errors.Is(err, identity.ErrInvalidChallenge) {
		t.Fatalf("clock rollback revived expired challenge: %v", err)
	}
}
