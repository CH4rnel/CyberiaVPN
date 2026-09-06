package identity

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

func TestIssueEnrollmentChallenge(t *testing.T) {
	now := time.Unix(1800000000, 0)
	store, err := NewEnrollmentStore(time.Minute, 2)
	if err != nil {
		t.Fatal(err)
	}
	first, err := store.Issue("account-1", "device-1", now)
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.Issue("account-1", "device-1", now)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Value) != 32 || bytes.Equal(first.Value, second.Value) || !first.ExpiresAt.Equal(now.Add(time.Minute)) {
		t.Fatalf("invalid challenges: %+v %+v", first, second)
	}
	if _, err := store.Issue("account-1", "device-1", now); !errors.Is(err, ErrEnrollmentCapacity) {
		t.Fatalf("capacity error: %v", err)
	}
}

func TestRejectInvalidChallengePolicyAndIdentity(t *testing.T) {
	for _, ttl := range []time.Duration{0, -time.Second, 11 * time.Minute} {
		if _, err := NewEnrollmentStore(ttl, 1); err == nil {
			t.Fatalf("accepted ttl %v", ttl)
		}
	}
	if _, err := NewEnrollmentStore(time.Minute, 0); err == nil {
		t.Fatal("accepted zero capacity")
	}
	store, _ := NewEnrollmentStore(time.Minute, 1)
	for _, ids := range [][2]string{{"", "device"}, {"account", "INVALID"}} {
		if _, err := store.Issue(ids[0], ids[1], time.Now()); !errors.Is(err, ErrInvalidEnrollment) {
			t.Fatalf("invalid identity: %v", err)
		}
	}
}

func TestConsumeBindsIdentityAndExpires(t *testing.T) {
	now := time.Unix(1800000000, 0)
	store, _ := NewEnrollmentStore(time.Minute, 10)
	challenge, _ := store.Issue("account", "device", now)
	for _, ids := range [][2]string{{"other", "device"}, {"account", "other"}} {
		if err := store.Consume(ids[0], ids[1], challenge.Value, now); !errors.Is(err, ErrInvalidChallenge) {
			t.Fatalf("cross-identity consume: %v", err)
		}
	}
	if err := store.Consume("account", "device", challenge.Value, now); err != nil {
		t.Fatal(err)
	}
	if err := store.Consume("account", "device", challenge.Value, now); !errors.Is(err, ErrInvalidChallenge) {
		t.Fatalf("replay: %v", err)
	}
	challenge, _ = store.Issue("account", "device", now)
	if err := store.Consume("account", "device", challenge.Value, challenge.ExpiresAt); !errors.Is(err, ErrInvalidChallenge) {
		t.Fatalf("expiry: %v", err)
	}
	if err := store.Consume("account", "device", []byte("unknown"), now); !errors.Is(err, ErrInvalidChallenge) {
		t.Fatalf("unknown: %v", err)
	}
}

func TestConcurrentChallengeConsumption(t *testing.T) {
	now := time.Now()
	store, _ := NewEnrollmentStore(time.Minute, 1)
	challenge, _ := store.Issue("account", "device", now)
	results := make(chan error, 20)
	for range 20 {
		go func() { results <- store.Consume("account", "device", challenge.Value, now) }()
	}
	successes := 0
	for range 20 {
		if err := <-results; err == nil {
			successes++
		} else if !errors.Is(err, ErrInvalidChallenge) {
			t.Fatal(err)
		}
	}
	if successes != 1 {
		t.Fatalf("successful consumers = %d", successes)
	}
}

func enrollmentRequest(t *testing.T, store *EnrollmentStore, account, device string, now time.Time) EnrollmentRequest {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := store.Issue(account, device, now)
	if err != nil {
		t.Fatal(err)
	}
	request := EnrollmentRequest{AccountID: account, DeviceID: device, PublicKey: public, Challenge: challenge.Value}
	request.Signature = ed25519.Sign(private, request.SigningMessage())
	return request
}

func TestEnrollVerifiesBeforeConsuming(t *testing.T) {
	now := time.Now()
	store, _ := NewEnrollmentStore(time.Minute, 10)
	request := enrollmentRequest(t, store, "account", "device", now)
	bad := request
	bad.Signature = make([]byte, ed25519.SignatureSize)
	if _, err := store.Enroll(bad, now); !errors.Is(err, ErrInvalidProof) {
		t.Fatalf("invalid proof: %v", err)
	}
	device, err := store.Enroll(request, now)
	if err != nil {
		t.Fatal(err)
	}
	if device.AccountID != request.AccountID || !bytes.Equal(device.PublicKey, request.PublicKey) {
		t.Fatalf("device: %+v", device)
	}
	if _, err := store.Enroll(request, now); err == nil {
		t.Fatal("accepted replay")
	}
	other := enrollmentRequest(t, store, "other-account", "device", now)
	if _, err := store.Enroll(other, now); !errors.Is(err, ErrDeviceExists) {
		t.Fatalf("device takeover: %v", err)
	}
}

func TestConcurrentEnrollmentHasOneWinner(t *testing.T) {
	now := time.Now()
	store, _ := NewEnrollmentStore(time.Minute, 10)
	request := enrollmentRequest(t, store, "account", "device", now)
	results := make(chan error, 20)
	for range 20 {
		go func() { _, err := store.Enroll(request, now); results <- err }()
	}
	successes := 0
	for range 20 {
		if err := <-results; err == nil {
			successes++
		} else if !errors.Is(err, ErrDeviceExists) && !errors.Is(err, ErrInvalidChallenge) {
			t.Fatal(err)
		}
	}
	if successes != 1 {
		t.Fatalf("enrollments = %d", successes)
	}
}

func TestEnrollRejectsExpiredAndUnissuedChallenges(t *testing.T) {
	now := time.Now()
	store, _ := NewEnrollmentStore(time.Minute, 10)
	request := enrollmentRequest(t, store, "account", "device", now)
	other, _ := NewEnrollmentStore(time.Minute, 10)
	if _, err := other.Enroll(request, now); !errors.Is(err, ErrInvalidChallenge) {
		t.Fatalf("unissued: %v", err)
	}
	if _, err := store.Enroll(request, now.Add(time.Minute)); !errors.Is(err, ErrInvalidChallenge) {
		t.Fatalf("expired: %v", err)
	}
}

func TestDeviceLookupIsAccountScopedAndOwnsKeys(t *testing.T) {
	now := time.Now()
	store, _ := NewEnrollmentStore(time.Minute, 10)
	request := enrollmentRequest(t, store, "account", "device", now)
	expected := bytes.Clone(request.PublicKey)
	registered, err := store.Enroll(request, now)
	if err != nil {
		t.Fatal(err)
	}
	request.PublicKey[0] ^= 255
	registered.PublicKey[1] ^= 255
	for _, ids := range [][2]string{{"other", "device"}, {"account", "missing"}} {
		if _, err := store.Device(ids[0], ids[1]); !errors.Is(err, ErrDeviceNotFound) {
			t.Fatalf("lookup: %v", err)
		}
	}
	found, err := store.Device("account", "device")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(found.PublicKey, expected) {
		t.Fatal("stored key aliases enrollment")
	}
	found.PublicKey[2] ^= 255
	again, err := store.Device("account", "device")
	if err != nil || !bytes.Equal(again.PublicKey, expected) {
		t.Fatal("stored key aliases read")
	}
}

func TestExpiredChallengesReleaseCapacity(t *testing.T) {
	now := time.Now()
	store, _ := NewEnrollmentStore(time.Minute, 1)
	expired, _ := store.Issue("account", "old", now)
	fresh, err := store.Issue("account", "new", expired.ExpiresAt)
	if err != nil {
		t.Fatalf("expired entry blocks issuance: %v", err)
	}
	if err := store.Consume("account", "old", expired.Value, now); !errors.Is(err, ErrInvalidChallenge) {
		t.Fatalf("pruned nonce restored: %v", err)
	}
	if err := store.Consume("account", "new", fresh.Value, expired.ExpiresAt); err != nil {
		t.Fatal(err)
	}
}

func TestDeviceCapacityDoesNotConsumeChallenge(t *testing.T) {
	now := time.Now()
	store, _ := NewEnrollmentStore(time.Minute, 1)
	first := enrollmentRequest(t, store, "account", "first", now)
	if _, err := store.Enroll(first, now); err != nil {
		t.Fatal(err)
	}
	second := enrollmentRequest(t, store, "account", "second", now)
	if _, err := store.Enroll(second, now); !errors.Is(err, ErrEnrollmentCapacity) {
		t.Fatalf("device capacity: %v", err)
	}
	if err := store.Consume("account", "second", second.Challenge, now); err != nil {
		t.Fatalf("capacity failure consumed nonce: %v", err)
	}
}
