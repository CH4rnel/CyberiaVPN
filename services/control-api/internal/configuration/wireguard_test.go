package configuration_test

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/CH4rnel/CyberiaVPN/services/control-api/internal/configuration"
)

func TestWireGuardParametersRejectUnsafePublicSettings(t *testing.T) {
	for _, mutate := range []func(*configuration.WireGuardParameters){
		func(parameters *configuration.WireGuardParameters) { parameters.PeerPublicKey = nil },
		func(parameters *configuration.WireGuardParameters) { parameters.PeerPublicKey = make([]byte, 32) },
		func(parameters *configuration.WireGuardParameters) { parameters.TunnelAddresses = nil },
		func(parameters *configuration.WireGuardParameters) {
			parameters.TunnelAddresses = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
		},
		func(parameters *configuration.WireGuardParameters) {
			parameters.TunnelAddresses = []netip.Prefix{netip.MustParsePrefix("10.0.0.2/24"), netip.MustParsePrefix("10.0.0.2/32")}
		},
		func(parameters *configuration.WireGuardParameters) { parameters.MTU = 1279 },
		func(parameters *configuration.WireGuardParameters) { parameters.PersistentKeepaliveSecond = 301 },
		func(parameters *configuration.WireGuardParameters) { parameters.AllowedIPs = nil },
		func(parameters *configuration.WireGuardParameters) {
			parameters.AllowedIPs = []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")}
		},
		func(parameters *configuration.WireGuardParameters) {
			parameters.AllowedIPs = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24"), netip.MustParsePrefix("10.0.0.0/24")}
		},
	} {
		config := validConfig(testNow())
		mutate(&config.WireGuard)
		if err := config.Validate(testNow()); !errors.Is(err, configuration.ErrInvalid) {
			t.Fatalf("error = %v", err)
		}
	}
}
