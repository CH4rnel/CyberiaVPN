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
	WireGuard WireGuardParameters
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// WireGuardParameters contains the public peer and interface fields required
// to establish a tunnel. Device private keys never appear in this structure.
type WireGuardParameters struct {
	PeerPublicKey             []byte
	TunnelAddresses           []netip.Prefix
	MTU                       uint16
	PersistentKeepaliveSecond uint16
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
	address := config.Endpoint.Addr().Unmap()
	if !config.Endpoint.IsValid() || config.Endpoint.Port() == 0 ||
		address.IsUnspecified() || address.IsMulticast() || config.Endpoint.Addr().Zone() != "" {
		return fmt.Errorf("%w: endpoint must contain an unscoped unicast IP address and nonzero port", ErrInvalid)
	}
	if len(config.DNS) == 0 {
		return fmt.Errorf("%w: at least one DNS resolver is required", ErrInvalid)
	}
	if err := config.WireGuard.Validate(); err != nil {
		return err
	}
	resolvers := make(map[netip.Addr]struct{}, len(config.DNS))
	for _, resolver := range config.DNS {
		address := resolver.Unmap()
		if !address.IsValid() || address.IsUnspecified() || address.IsMulticast() || resolver.Zone() != "" {
			return fmt.Errorf("%w: invalid DNS resolver", ErrInvalid)
		}
		if _, exists := resolvers[address]; exists {
			return fmt.Errorf("%w: duplicate DNS resolver", ErrInvalid)
		}
		resolvers[address] = struct{}{}
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

func (parameters WireGuardParameters) Validate() error {
	if len(parameters.PeerPublicKey) != 32 {
		return fmt.Errorf("%w: WireGuard peer public key must be 32 bytes", ErrInvalid)
	}
	allZero := true
	for _, byte := range parameters.PeerPublicKey {
		if byte != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return fmt.Errorf("%w: WireGuard peer public key is zero", ErrInvalid)
	}
	if len(parameters.TunnelAddresses) == 0 || len(parameters.TunnelAddresses) > 16 {
		return fmt.Errorf("%w: WireGuard requires between 1 and 16 tunnel addresses", ErrInvalid)
	}
	addresses := make(map[netip.Addr]struct{}, len(parameters.TunnelAddresses))
	for _, prefix := range parameters.TunnelAddresses {
		address := prefix.Addr()
		if !prefix.IsValid() || address.IsUnspecified() || address.IsMulticast() || address.Zone() != "" {
			return fmt.Errorf("%w: invalid WireGuard tunnel address", ErrInvalid)
		}
		if _, exists := addresses[address]; exists {
			return fmt.Errorf("%w: duplicate WireGuard tunnel address", ErrInvalid)
		}
		addresses[address] = struct{}{}
	}
	if parameters.MTU < 1280 || parameters.MTU > 9000 {
		return fmt.Errorf("%w: WireGuard MTU is outside safe bounds", ErrInvalid)
	}
	if parameters.PersistentKeepaliveSecond > 300 {
		return fmt.Errorf("%w: WireGuard keepalive is outside safe bounds", ErrInvalid)
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
