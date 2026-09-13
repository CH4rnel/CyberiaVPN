package configuration

import (
	"encoding/json"
	"errors"
	"os"
	"sync"
	"time"

	"github.com/CH4rnel/CyberiaVPN/services/control-api/internal/snapshot"
)

// ClientState durably records a device's highest accepted configuration version.
// Persist acceptance before configuring a tunnel, so a crash cannot permit a
// later rollback. One state file belongs to one trusted device ID.
type ClientState struct {
	mu       sync.Mutex
	file     *snapshot.File
	deviceID string
	version  uint64
}
type clientSnapshot struct {
	Schema   int    `json:"schema"`
	DeviceID string `json:"device_id"`
	Version  uint64 `json:"version"`
}

func OpenClientState(path, deviceID string) (*ClientState, error) {
	if !validIdentifier(deviceID) {
		return nil, errors.New("client device ID must be a lowercase slug")
	}
	file, err := snapshot.Open(path, 4096)
	if err != nil {
		return nil, err
	}
	state := &ClientState{file: file, deviceID: deviceID}
	data, err := file.Read()
	if errors.Is(err, os.ErrNotExist) {
		err = state.save(0)
	} else if err == nil {
		var persisted clientSnapshot
		if err = snapshot.Decode(data, &persisted); err == nil && (persisted.Schema != 1 || persisted.DeviceID != deviceID) {
			err = errors.New("client state belongs to a different device")
		}
		if err == nil {
			state.version = persisted.Version
		}
	}
	if err != nil {
		file.Close()
		return nil, err
	}
	return state, nil
}

func (state *ClientState) save(version uint64) error {
	data, err := json.Marshal(clientSnapshot{Schema: 1, DeviceID: state.deviceID, Version: version})
	if err != nil {
		return err
	}
	return state.file.Write(data)
}

func (state *ClientState) Accept(envelope SignedConfig, now time.Time, verifier Verifier) (DeviceConfig, error) {
	state.mu.Lock()
	defer state.mu.Unlock()
	if err := state.file.Check(); err != nil {
		return DeviceConfig{}, err
	}
	config, err := OpenForDevice(envelope, state.deviceID, state.version, now, verifier)
	if err != nil {
		return DeviceConfig{}, err
	}
	if err := state.save(config.Version); err != nil {
		return DeviceConfig{}, err
	}
	state.version = config.Version
	return config, nil
}
func (state *ClientState) Version() uint64 {
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.version
}
func (state *ClientState) Close() error {
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.file.Close()
}
