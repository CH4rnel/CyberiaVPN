package configuration_test

import (
	"crypto/ed25519"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/CH4rnel/CyberiaVPN/services/control-api/internal/configuration"
)

func TestOpenForDevice(t *testing.T) {
	now := testNow()
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	signer, err := configuration.NewEd25519Signer("test-key", private)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := configuration.NewEd25519Verifier(map[string]ed25519.PublicKey{"test-key": private.Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, device      string
		version, accepted uint64
		at                time.Time
		tamper            bool
		want              error
	}{
		{"first", "laptop-1", 1, 0, now, false, nil},
		{"upgrade", "laptop-1", 3, 1, now, false, nil},
		{"replay", "laptop-1", 1, 1, now, false, configuration.ErrStaleVersion},
		{"rollback", "laptop-1", 1, 2, now, false, configuration.ErrStaleVersion},
		{"version overflow", "laptop-1", 1, math.MaxUint64, now, false, configuration.ErrStaleVersion},
		{"foreign device", "other", 1, 0, now, false, configuration.ErrDeviceMismatch},
		{"empty device", "", 1, 0, now, false, configuration.ErrDeviceMismatch},
		{"expired", "laptop-1", 1, 0, now.Add(time.Hour), false, configuration.ErrExpired},
		{"forged upgrade", "laptop-1", 1, 1, now, true, configuration.ErrInvalidSignature},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := validConfig(now)
			config.Version = tc.version
			envelope, err := configuration.Seal(config, now, signer)
			if err != nil {
				t.Fatal(err)
			}
			if tc.tamper {
				envelope.Config.Version++
			}
			opened, err := configuration.OpenForDevice(envelope, tc.device, tc.accepted, tc.at, verifier)
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
			if tc.want == nil && opened.Version != tc.version {
				t.Fatalf("version = %d", opened.Version)
			}
			if tc.want != nil && opened.DeviceID != "" {
				t.Fatal("returned rejected configuration")
			}
		})
	}
}
