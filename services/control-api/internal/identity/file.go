package identity

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"time"

	"github.com/CH4rnel/CyberiaVPN/services/control-api/internal/snapshot"
)

// FileEnrollmentStore persists a single-instance enrollment transaction before
// acknowledging it. A failed write never publishes candidate in-memory state.
type FileEnrollmentStore struct {
	mu      sync.Mutex
	file    *snapshot.File
	current *EnrollmentStore
}

type enrollmentSnapshot struct {
	Schema     int                 `json:"schema"`
	Devices    []DeviceIdentity    `json:"devices"`
	Challenges []challengeSnapshot `json:"challenges"`
}

type challengeSnapshot struct {
	Digest    []byte    `json:"digest"`
	AccountID string    `json:"account_id"`
	DeviceID  string    `json:"device_id"`
	ExpiresAt time.Time `json:"expires_at"`
}

func OpenFileEnrollmentStore(path string, ttl time.Duration, capacity int) (*FileEnrollmentStore, error) {
	current, err := NewEnrollmentStore(ttl, capacity)
	if err != nil {
		return nil, err
	}
	if capacity > 10000 {
		return nil, errors.New("durable enrollment capacity exceeds 10000")
	}
	file, err := snapshot.Open(path, 16<<20)
	if err != nil {
		return nil, err
	}
	store := &FileEnrollmentStore{file: file, current: current}
	data, err := file.Read()
	if errors.Is(err, os.ErrNotExist) {
		err = store.persist(current)
	} else if err == nil {
		err = store.restore(data)
	}
	if err != nil {
		file.Close()
		return nil, err
	}
	return store, nil
}

func (store *FileEnrollmentStore) restore(data []byte) error {
	var state enrollmentSnapshot
	if err := snapshot.Decode(data, &state); err != nil {
		return err
	}
	if state.Schema != 1 || state.Devices == nil || state.Challenges == nil || len(state.Devices) > store.current.capacity || len(state.Challenges) > store.current.capacity {
		return errors.New("invalid enrollment snapshot schema or capacity")
	}
	store.current.devices = make(map[string]DeviceIdentity, len(state.Devices))
	for _, device := range state.Devices {
		digest := sha256.Sum256(device.PublicKey)
		if !validIdentifier(device.AccountID) || !validIdentifier(device.DeviceID) || len(device.PublicKey) != ed25519.PublicKeySize || device.KeyID != hex.EncodeToString(digest[:]) {
			return errors.New("invalid persisted device")
		}
		if _, exists := store.current.devices[device.DeviceID]; exists {
			return errors.New("duplicate persisted device")
		}
		store.current.devices[device.DeviceID] = cloneDevice(device)
	}
	for _, challenge := range state.Challenges {
		if len(challenge.Digest) != sha256.Size || !validIdentifier(challenge.AccountID) || !validIdentifier(challenge.DeviceID) || challenge.ExpiresAt.IsZero() {
			return errors.New("invalid persisted challenge")
		}
		digest := [32]byte(challenge.Digest)
		if _, exists := store.current.challenges[digest]; exists {
			return errors.New("duplicate persisted challenge")
		}
		store.current.challenges[digest] = pendingChallenge{accountID: challenge.AccountID, deviceID: challenge.DeviceID, expiresAt: challenge.ExpiresAt}
	}
	return nil
}

func (store *FileEnrollmentStore) persist(candidate *EnrollmentStore) error {
	state := enrollmentSnapshot{Schema: 1, Devices: make([]DeviceIdentity, 0, len(candidate.devices)), Challenges: make([]challengeSnapshot, 0, len(candidate.challenges))}
	for _, device := range candidate.devices {
		state.Devices = append(state.Devices, device)
	}
	for digest, challenge := range candidate.challenges {
		state.Challenges = append(state.Challenges, challengeSnapshot{Digest: digest[:], AccountID: challenge.accountID, DeviceID: challenge.deviceID, ExpiresAt: challenge.expiresAt})
	}
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	if err := store.file.Write(data); err != nil {
		return err
	}
	store.current = candidate
	return nil
}

func (store *FileEnrollmentStore) candidate() *EnrollmentStore {
	current := store.current
	candidate := &EnrollmentStore{ttl: current.ttl, capacity: current.capacity, devices: make(map[string]DeviceIdentity, len(current.devices)), challenges: make(map[[32]byte]pendingChallenge, len(current.challenges))}
	for id, device := range current.devices {
		candidate.devices[id] = cloneDevice(device)
	}
	for digest, challenge := range current.challenges {
		candidate.challenges[digest] = challenge
	}
	return candidate
}

func (store *FileEnrollmentStore) Issue(accountID, deviceID string, now time.Time) (Challenge, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.file.Check(); err != nil {
		return Challenge{}, err
	}
	candidate := store.candidate()
	challenge, err := candidate.Issue(accountID, deviceID, now)
	if err != nil {
		return Challenge{}, err
	}
	if err := store.persist(candidate); err != nil {
		return Challenge{}, err
	}
	return challenge, nil
}

func (store *FileEnrollmentStore) Enroll(request EnrollmentRequest, now time.Time) (DeviceIdentity, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.file.Check(); err != nil {
		return DeviceIdentity{}, err
	}
	candidate := store.candidate()
	device, domainErr := candidate.Enroll(request, now)
	// Expiration can consume a stale challenge even when enrollment is rejected.
	if domainErr == nil || len(candidate.challenges) != len(store.current.challenges) {
		if err := store.persist(candidate); err != nil {
			return DeviceIdentity{}, err
		}
	}
	return device, domainErr
}

func (store *FileEnrollmentStore) Device(accountID, deviceID string) (DeviceIdentity, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.file.Check(); err != nil {
		return DeviceIdentity{}, err
	}
	return store.current.Device(accountID, deviceID)
}

func (store *FileEnrollmentStore) Close() error {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.file.Close()
}
