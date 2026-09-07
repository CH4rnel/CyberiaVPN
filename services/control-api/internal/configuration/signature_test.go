package configuration_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/CH4rnel/CyberiaVPN/services/control-api/internal/configuration"
)

func TestSealAndVerifyConfiguration(t *testing.T) {
	now := time.Unix(1_788_563_400, 0).UTC()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	signer, err := configuration.NewEd25519Signer("config-key-1", privateKey)
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}
	verifier, err := configuration.NewEd25519Verifier(map[string]ed25519.PublicKey{
		"config-key-1": publicKey,
	})
	if err != nil {
		t.Fatalf("create verifier: %v", err)
	}

	envelope, err := configuration.Seal(validConfig(now), now, signer)
	if err != nil {
		t.Fatalf("seal config: %v", err)
	}
	verified, err := configuration.Open(envelope, now, verifier)

	if err != nil {
		t.Fatalf("open config: %v", err)
	}
	if verified.Version != 1 || verified.DeviceID != "laptop-1" {
		t.Errorf("verified config = %+v", verified)
	}
}

func TestRejectsTamperedConfiguration(t *testing.T) {
	now := time.Unix(1_788_563_400, 0).UTC()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	signer, err := configuration.NewEd25519Signer("config-key-1", privateKey)
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}
	verifier, err := configuration.NewEd25519Verifier(map[string]ed25519.PublicKey{
		"config-key-1": publicKey,
	})
	if err != nil {
		t.Fatalf("create verifier: %v", err)
	}
	envelope, err := configuration.Seal(validConfig(now), now, signer)
	if err != nil {
		t.Fatalf("seal config: %v", err)
	}
	envelope.Config.Endpoint = netip.MustParseAddrPort("198.51.100.20:51820")

	_, err = configuration.Open(envelope, now, verifier)

	if !errors.Is(err, configuration.ErrInvalidSignature) {
		t.Fatalf("error = %v, want ErrInvalidSignature", err)
	}
}

func TestRejectsUnknownConfigurationSigningKey(t *testing.T) {
	now := time.Unix(1_788_563_400, 0).UTC()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	signer, err := configuration.NewEd25519Signer("retired-key", privateKey)
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}
	verifier, err := configuration.NewEd25519Verifier(nil)
	if err != nil {
		t.Fatalf("create verifier: %v", err)
	}
	envelope, err := configuration.Seal(validConfig(now), now, signer)
	if err != nil {
		t.Fatalf("seal config: %v", err)
	}

	_, err = configuration.Open(envelope, now, verifier)

	if !errors.Is(err, configuration.ErrUnknownSigningKey) {
		t.Fatalf("error = %v, want ErrUnknownSigningKey", err)
	}
}

func TestSignatureBindsSubsecondValidity(t *testing.T) {
	now := time.Unix(1_788_563_400, 123456789).UTC()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := configuration.NewEd25519Signer("config-key-1", private)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := configuration.NewEd25519Verifier(map[string]ed25519.PublicKey{"config-key-1": public})
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := configuration.Seal(validConfig(now), now, signer)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := configuration.Open(envelope, now, verifier)
	if err != nil || !opened.IssuedAt.Equal(envelope.Config.IssuedAt) || !opened.ExpiresAt.Equal(envelope.Config.ExpiresAt) {
		t.Fatalf("round trip: %+v, %v", opened, err)
	}
	for _, field := range []string{"issued_at", "expires_at"} {
		t.Run(field, func(t *testing.T) {
			tampered := envelope
			if field == "issued_at" {
				tampered.Config.IssuedAt = tampered.Config.IssuedAt.Add(time.Nanosecond)
			} else {
				tampered.Config.ExpiresAt = tampered.Config.ExpiresAt.Add(time.Nanosecond)
			}
			if _, err := configuration.Open(tampered, now, verifier); !errors.Is(err, configuration.ErrInvalidSignature) {
				t.Fatalf("subsecond tampering accepted: %v", err)
			}
		})
	}
	// A different timezone representation of the same instant stays valid.
	envelope.Config.IssuedAt = envelope.Config.IssuedAt.In(time.FixedZone("test", 3600))
	if _, err := configuration.Open(envelope, now, verifier); err != nil {
		t.Fatalf("equivalent instant rejected: %v", err)
	}
}
