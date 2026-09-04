package configuration

import (
	"errors"
	"fmt"
	"net/netip"
	"time"
)

var (
	ErrInvalid = errors.New("invalid device configuration")
	ErrExpired = errors.New("device configuration expired")
)

const (
	TransportWireGuard = "wireguard"
	maximumLifetime    = 24 * time.Hour
	maximumClockSkew   = 5 * time.Minute
)

// DeviceConfig contains public, short-lived connection parameters. Private
// device and transport keys are never configuration-delivery fields.
type DeviceConfig struct {
	Version   uint64
	DeviceID  string
	NodeID    string
	Transport string
	Endpoint  netip.AddrPort
	DNS       []netip.Addr
	IssuedAt  time.Time
	ExpiresAt time.Time
}

func (config DeviceConfig) Validate(now time.Time) error {
	if config.Version == 0 {
		return fmt.Errorf("%w: version must be positive", ErrInvalid)
	}
	if !validIdentifier(config.DeviceID) || !validIdentifier(config.NodeID) {
		return fmt.Errorf("%w: device and node IDs must be lowercase slugs", ErrInvalid)
	}
	if config.Transport != TransportWireGuard {
		return fmt.Errorf("%w: unsupported transport %q", ErrInvalid, config.Transport)
	}
	if !config.Endpoint.IsValid() || config.Endpoint.Port() == 0 {
		return fmt.Errorf("%w: endpoint must contain a valid IP address and port", ErrInvalid)
	}
	if len(config.DNS) == 0 {
		return fmt.Errorf("%w: at least one DNS resolver is required", ErrInvalid)
	}
	for _, resolver := range config.DNS {
		if !resolver.IsValid() || resolver.IsUnspecified() || resolver.IsMulticast() {
			return fmt.Errorf("%w: invalid DNS resolver", ErrInvalid)
		}
	}
	if config.IssuedAt.IsZero() || config.ExpiresAt.IsZero() ||
		!config.ExpiresAt.After(config.IssuedAt) {
		return fmt.Errorf("%w: invalid validity interval", ErrInvalid)
	}
	if config.ExpiresAt.Sub(config.IssuedAt) > maximumLifetime {
		return fmt.Errorf("%w: lifetime exceeds %s", ErrInvalid, maximumLifetime)
	}
	if config.IssuedAt.After(now.Add(maximumClockSkew)) {
		return fmt.Errorf("%w: issued-at time is in the future", ErrInvalid)
	}
	if !config.ExpiresAt.After(now) {
		return ErrExpired
	}
	return nil
}

func validIdentifier(value string) bool {
	if value == "" || len(value) > 63 || value[0] == '-' || value[len(value)-1] == '-' {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') &&
			(character < '0' || character > '9') && character != '-' {
			return false
		}
	}
	return true
}
