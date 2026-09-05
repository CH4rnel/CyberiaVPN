package configuration

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
)

var (
	ErrStaleVersion   = errors.New("configuration version is stale")
	ErrConfigNotFound = errors.New("device configuration not found")
)

// Store is the narrow persistence boundary required by configuration
// delivery. Durable implementations can replace MemoryStore unchanged.
type Store interface {
	Publish(SignedConfig) error
	Latest(deviceID string) (SignedConfig, error)
}

// MemoryStore keeps envelopes in memory. Its zero value is ready for use.
// A MemoryStore must not be copied after first use.
type MemoryStore struct {
	mu      sync.RWMutex
	devices map[string]SignedConfig
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{devices: make(map[string]SignedConfig)}
}

func (store *MemoryStore) Publish(envelope SignedConfig) error {
	if !validIdentifier(envelope.Config.DeviceID) || envelope.Config.Version == 0 ||
		!validIdentifier(envelope.KeyID) || len(envelope.Signature) == 0 {
		return fmt.Errorf("%w: incomplete signed envelope", ErrInvalid)
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	current, exists := store.devices[envelope.Config.DeviceID]
	if exists && envelope.Config.Version <= current.Config.Version {
		return fmt.Errorf(
			"%w: current=%d proposed=%d",
			ErrStaleVersion,
			current.Config.Version,
			envelope.Config.Version,
		)
	}
	if store.devices == nil {
		store.devices = make(map[string]SignedConfig)
	}
	store.devices[envelope.Config.DeviceID] = cloneEnvelope(envelope)
	return nil
}

func (store *MemoryStore) Latest(deviceID string) (SignedConfig, error) {
	store.mu.RLock()
	defer store.mu.RUnlock()
	envelope, exists := store.devices[deviceID]
	if !exists {
		return SignedConfig{}, ErrConfigNotFound
	}
	return cloneEnvelope(envelope), nil
}

func cloneEnvelope(envelope SignedConfig) SignedConfig {
	envelope.Config = cloneConfig(envelope.Config)
	envelope.Signature = bytes.Clone(envelope.Signature)
	return envelope
}
