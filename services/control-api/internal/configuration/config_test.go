package configuration_test

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/CH4rnel/CyberiaVPN/services/control-api/internal/configuration"
)

func TestAcceptsBoundedWireGuardConfiguration(t *testing.T) {
	now := time.Unix(1_788_563_400, 0).UTC()
	config := validConfig(now)

	if err := config.Validate(now); err != nil {
		t.Fatalf("validate config: %v", err)
	}
}

func TestRejectsExpiredConfiguration(t *testing.T) {
	now := time.Unix(1_788_563_400, 0).UTC()
	config := validConfig(now)
	config.ExpiresAt = now

	err := config.Validate(now)

	if !errors.Is(err, configuration.ErrExpired) {
		t.Fatalf("error = %v, want ErrExpired", err)
	}
}

func TestRejectsExcessiveConfigurationLifetime(t *testing.T) {
	now := time.Unix(1_788_563_400, 0).UTC()
	config := validConfig(now)
	config.ExpiresAt = config.IssuedAt.Add(25 * time.Hour)

	err := config.Validate(now)

	if !errors.Is(err, configuration.ErrInvalid) {
		t.Fatalf("error = %v, want ErrInvalid", err)
	}
}

func TestRejectsUnknownTransport(t *testing.T) {
	now := time.Unix(1_788_563_400, 0).UTC()
	config := validConfig(now)
	config.Transport = "experimental"

	err := config.Validate(now)

	if !errors.Is(err, configuration.ErrInvalid) {
		t.Fatalf("error = %v, want ErrInvalid", err)
	}
}

func validConfig(now time.Time) configuration.DeviceConfig {
	return configuration.DeviceConfig{
		Version:   1,
		DeviceID:  "laptop-1",
		NodeID:    "de-fra-1",
		Transport: configuration.TransportWireGuard,
		Endpoint:  netip.MustParseAddrPort("192.0.2.10:51820"),
		DNS:       []netip.Addr{netip.MustParseAddr("192.0.2.53")},
		IssuedAt:  now.Add(-time.Minute),
		ExpiresAt: now.Add(time.Hour),
	}
}

func TestRejectsUnusableEndpoints(t *testing.T) {
	for _, address := range []string{"0.0.0.0:51820", "[::]:51820", "224.0.0.1:51820", "[ff02::1]:51820", "[::ffff:224.0.0.1]:51820", "[fe80::1%eth0]:51820"} {
		t.Run(address, func(t *testing.T) {
			config := validConfig(testNow())
			config.Endpoint = netip.MustParseAddrPort(address)
			if err := config.Validate(testNow()); !errors.Is(err, configuration.ErrInvalid) {
				t.Fatalf("error = %v, want ErrInvalid", err)
			}
		})
	}
}
