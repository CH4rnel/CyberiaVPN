package configuration

import (
	"encoding/json"
	"errors"
	"os"
	"sync"

	"github.com/CH4rnel/CyberiaVPN/services/control-api/internal/snapshot"
)

// FileStore atomically persists latest signed envelopes. It is a single-process
// store; callers must use a database or object store for multi-instance APIs.
type FileStore struct {
	mu   sync.Mutex
	file *snapshot.File
	data *MemoryStore
}

type fileState struct {
	Schema    int            `json:"schema"`
	Envelopes []SignedConfig `json:"envelopes"`
}

func OpenFileStore(path string) (*FileStore, error) {
	file, err := snapshot.Open(path, 16<<20)
	if err != nil {
		return nil, err
	}
	store := &FileStore{file: file, data: NewMemoryStore()}
	data, err := file.Read()
	if errors.Is(err, os.ErrNotExist) {
		err = store.save(store.data)
	} else if err == nil {
		err = store.load(data)
	}
	if err != nil {
		file.Close()
		return nil, err
	}
	return store, nil
}

func (store *FileStore) load(data []byte) error {
	var state fileState
	if err := snapshot.Decode(data, &state); err != nil {
		return err
	}
	if state.Schema != 1 || state.Envelopes == nil || len(state.Envelopes) > 10000 {
		return errors.New("invalid configuration snapshot")
	}
	for _, envelope := range state.Envelopes {
		if err := store.data.Publish(envelope); err != nil {
			return errors.New("invalid persisted configuration")
		}
	}
	return nil
}

func (store *FileStore) save(candidate *MemoryStore) error {
	candidate.mu.RLock()
	state := fileState{Schema: 1, Envelopes: make([]SignedConfig, 0, len(candidate.devices))}
	for _, envelope := range candidate.devices {
		state.Envelopes = append(state.Envelopes, cloneEnvelope(envelope))
	}
	candidate.mu.RUnlock()
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return store.file.Write(data)
}

func (store *FileStore) clone() *MemoryStore {
	candidate := NewMemoryStore()
	store.data.mu.RLock()
	for deviceID, envelope := range store.data.devices {
		candidate.devices[deviceID] = cloneEnvelope(envelope)
	}
	store.data.mu.RUnlock()
	return candidate
}

func (store *FileStore) Publish(envelope SignedConfig) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.file.Check(); err != nil {
		return err
	}
	candidate := store.clone()
	if err := candidate.Publish(envelope); err != nil {
		return err
	}
	if err := store.save(candidate); err != nil {
		return err
	}
	store.data = candidate
	return nil
}

func (store *FileStore) Latest(deviceID string) (SignedConfig, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.file.Check(); err != nil {
		return SignedConfig{}, err
	}
	return store.data.Latest(deviceID)
}

func (store *FileStore) Close() error {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.file.Close()
}
