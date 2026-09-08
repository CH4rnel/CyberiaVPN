package configuration

import (
	"errors"
	"time"
)

var ErrDeviceMismatch = errors.New("configuration belongs to a different device")

// OpenForDevice verifies an update against a trusted local device ID and the
// highest previously accepted version. Zero allows the first configuration.
// Callers must serialize acceptance and durably record the returned version
// before applying it. Never obtain acceptedVersion from the incoming envelope;
// resetting it on restart loses rollback protection. Equal versions are replays.
func OpenForDevice(envelope SignedConfig, deviceID string, acceptedVersion uint64, now time.Time, verifier Verifier) (DeviceConfig, error) {
	config, err := Open(envelope, now, verifier)
	if err != nil {
		return DeviceConfig{}, err
	}
	if config.DeviceID != deviceID {
		return DeviceConfig{}, ErrDeviceMismatch
	}
	if config.Version <= acceptedVersion {
		return DeviceConfig{}, ErrStaleVersion
	}
	return config, nil
}
