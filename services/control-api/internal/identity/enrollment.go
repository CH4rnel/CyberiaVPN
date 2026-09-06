package identity

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"time"
)

var ErrEnrollmentCapacity = errors.New("enrollment capacity reached")

// Challenge is an unpredictable server-issued enrollment nonce.
type Challenge struct {
	Value     []byte    `json:"challenge"`
	ExpiresAt time.Time `json:"expires_at"`
}

type pendingChallenge struct {
	accountID string
	deviceID  string
	expiresAt time.Time
}

// EnrollmentStore is process-local and must be constructed with NewEnrollmentStore.
// It must not be copied after first use. Methods are safe for concurrent calls.
type EnrollmentStore struct {
	devices    map[string]DeviceIdentity
	mu         sync.Mutex
	ttl        time.Duration
	capacity   int
	challenges map[[32]byte]pendingChallenge
}

func NewEnrollmentStore(ttl time.Duration, capacity int) (*EnrollmentStore, error) {
	if ttl <= 0 || ttl > 10*time.Minute || capacity <= 0 {
		return nil, fmt.Errorf("%w: TTL must be in (0, 10m] and capacity positive", ErrInvalidEnrollment)
	}
	return &EnrollmentStore{ttl: ttl, capacity: capacity, challenges: make(map[[32]byte]pendingChallenge)}, nil
}

func (store *EnrollmentStore) Issue(accountID, deviceID string, now time.Time) (Challenge, error) {
	if !validIdentifier(accountID) || !validIdentifier(deviceID) {
		return Challenge{}, ErrInvalidEnrollment
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.challenges) >= store.capacity {
		return Challenge{}, ErrEnrollmentCapacity
	}
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return Challenge{}, fmt.Errorf("generate challenge: %w", err)
	}
	digest := sha256.Sum256(value)
	if _, exists := store.challenges[digest]; exists {
		return Challenge{}, errors.New("challenge collision")
	}
	expiresAt := now.Add(store.ttl)
	store.challenges[digest] = pendingChallenge{accountID: accountID, deviceID: deviceID, expiresAt: expiresAt}
	return Challenge{Value: value, ExpiresAt: expiresAt}, nil
}

var ErrInvalidChallenge = errors.New("invalid or expired enrollment challenge")

// Consume atomically accepts a fresh challenge once. Registration should use
// Enroll once device persistence is required in the same transaction.
func (store *EnrollmentStore) Consume(accountID, deviceID string, value []byte, now time.Time) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.consumeLocked(accountID, deviceID, value, now)
}

func (store *EnrollmentStore) consumeLocked(accountID, deviceID string, value []byte, now time.Time) error {
	if len(value) != 32 {
		return ErrInvalidChallenge
	}
	digest := sha256.Sum256(value)
	pending, exists := store.challenges[digest]
	if !exists || pending.accountID != accountID || pending.deviceID != deviceID {
		return ErrInvalidChallenge
	}
	if !pending.expiresAt.After(now) {
		delete(store.challenges, digest)
		return ErrInvalidChallenge
	}
	delete(store.challenges, digest)
	return nil
}

var ErrDeviceExists = errors.New("device ID already registered")

// Enroll verifies proof before atomically consuming the nonce and registering
// a globally unique device ID. Existing devices cannot be overwritten.
func (store *EnrollmentStore) Enroll(request EnrollmentRequest, now time.Time) (DeviceIdentity, error) {
	device, err := VerifyEnrollment(request)
	if err != nil {
		return DeviceIdentity{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, exists := store.devices[device.DeviceID]; exists {
		return DeviceIdentity{}, ErrDeviceExists
	}
	if err := store.consumeLocked(device.AccountID, device.DeviceID, request.Challenge, now); err != nil {
		return DeviceIdentity{}, err
	}
	if store.devices == nil {
		store.devices = make(map[string]DeviceIdentity)
	}
	store.devices[device.DeviceID] = cloneDevice(device)
	return device, nil
}

func cloneDevice(device DeviceIdentity) DeviceIdentity {
	device.PublicKey = bytes.Clone(device.PublicKey)
	return device
}
