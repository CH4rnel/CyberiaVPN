package identity_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/CH4rnel/CyberiaVPN/services/control-api/internal/identity"
)

func TestVerifyDeviceEnrollmentProof(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	request := identity.EnrollmentRequest{
		AccountID: "account-1",
		DeviceID:  "laptop-1",
		PublicKey: publicKey,
		Challenge: []byte("0123456789abcdef0123456789abcdef"),
	}
	request.Signature = ed25519.Sign(privateKey, request.SigningMessage())

	device, err := identity.VerifyEnrollment(request)

	if err != nil {
		t.Fatalf("verify enrollment: %v", err)
	}
	if device.DeviceID != request.DeviceID || device.AccountID != request.AccountID {
		t.Errorf("device = %+v, want request identity", device)
	}
	if device.KeyID == "" {
		t.Error("key ID is empty")
	}
}

func TestRejectsEnrollmentIdentityTampering(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	request := identity.EnrollmentRequest{
		AccountID: "account-1",
		DeviceID:  "laptop-1",
		PublicKey: publicKey,
		Challenge: []byte("0123456789abcdef0123456789abcdef"),
	}
	request.Signature = ed25519.Sign(privateKey, request.SigningMessage())
	request.DeviceID = "attacker-device"

	_, err = identity.VerifyEnrollment(request)

	if !errors.Is(err, identity.ErrInvalidProof) {
		t.Fatalf("error = %v, want ErrInvalidProof", err)
	}
}

func TestRejectsWeakEnrollmentChallenge(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	request := identity.EnrollmentRequest{
		AccountID: "account-1",
		DeviceID:  "laptop-1",
		PublicKey: publicKey,
		Challenge: []byte("too-short"),
	}

	_, err = identity.VerifyEnrollment(request)

	if !errors.Is(err, identity.ErrInvalidEnrollment) {
		t.Fatalf("error = %v, want ErrInvalidEnrollment", err)
	}
}
