package identity

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
)

var (
	ErrInvalidEnrollment = errors.New("invalid device enrollment")
	ErrInvalidProof      = errors.New("invalid device proof")
)

const enrollmentDomain = "cyberia-device-enrollment:v1"

type EnrollmentRequest struct {
	AccountID string
	DeviceID  string
	PublicKey ed25519.PublicKey
	Challenge []byte
	Signature []byte
}

// SigningMessage binds proof-of-possession to the protocol version, account,
// device and server-issued challenge. Fields are length-prefixed to avoid
// ambiguous encodings.
func (request EnrollmentRequest) SigningMessage() []byte {
	message := make([]byte, 0, 128)
	for _, field := range [][]byte{
		[]byte(enrollmentDomain),
		[]byte(request.AccountID),
		[]byte(request.DeviceID),
		request.Challenge,
	} {
		message = binary.BigEndian.AppendUint32(message, uint32(len(field)))
		message = append(message, field...)
	}
	return message
}

type DeviceIdentity struct {
	AccountID string
	DeviceID  string
	PublicKey ed25519.PublicKey
	KeyID     string
}

// VerifyEnrollment validates a device's Ed25519 proof-of-possession. The
// caller remains responsible for atomically consuming a fresh, account-bound
// challenge after this verification succeeds.
func VerifyEnrollment(request EnrollmentRequest) (DeviceIdentity, error) {
	if !validIdentifier(request.AccountID) || !validIdentifier(request.DeviceID) {
		return DeviceIdentity{}, fmt.Errorf("%w: account and device IDs must be lowercase slugs", ErrInvalidEnrollment)
	}
	if len(request.PublicKey) != ed25519.PublicKeySize {
		return DeviceIdentity{}, fmt.Errorf("%w: invalid Ed25519 public key", ErrInvalidEnrollment)
	}
	if len(request.Challenge) < 32 || len(request.Challenge) > 256 {
		return DeviceIdentity{}, fmt.Errorf("%w: challenge length must be between 32 and 256 bytes", ErrInvalidEnrollment)
	}
	if len(request.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(request.PublicKey, request.SigningMessage(), request.Signature) {
		return DeviceIdentity{}, ErrInvalidProof
	}

	digest := sha256.Sum256(request.PublicKey)
	return DeviceIdentity{
		AccountID: request.AccountID,
		DeviceID:  request.DeviceID,
		PublicKey: bytes.Clone(request.PublicKey),
		KeyID:     hex.EncodeToString(digest[:]),
	}, nil
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
