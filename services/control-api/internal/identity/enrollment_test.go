package identity

import (
	"bytes"
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
