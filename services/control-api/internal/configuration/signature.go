package configuration

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"time"
)

var (
	ErrInvalidSignature  = errors.New("invalid configuration signature")
	ErrUnknownSigningKey = errors.New("unknown configuration signing key")
)

const configurationDomain = "cyberia-device-configuration:v1"

type Signer interface {
	KeyID() string
	Sign(message []byte) ([]byte, error)
}

type Verifier interface {
	Verify(keyID string, message, signature []byte) error
}

type SignedConfig struct {
	Config    DeviceConfig
	KeyID     string
	Signature []byte
}

type Ed25519Signer struct {
	keyID      string
	privateKey ed25519.PrivateKey
}

func NewEd25519Signer(keyID string, privateKey ed25519.PrivateKey) (*Ed25519Signer, error) {
	if !validIdentifier(keyID) {
		return nil, errors.New("signing key ID must be a lowercase slug")
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid Ed25519 private key")
	}
	return &Ed25519Signer{keyID: keyID, privateKey: bytes.Clone(privateKey)}, nil
}

func (signer *Ed25519Signer) KeyID() string {
	return signer.keyID
}

func (signer *Ed25519Signer) Sign(message []byte) ([]byte, error) {
	return ed25519.Sign(signer.privateKey, message), nil
}

type Ed25519Verifier struct {
	publicKeys map[string]ed25519.PublicKey
}

func NewEd25519Verifier(publicKeys map[string]ed25519.PublicKey) (*Ed25519Verifier, error) {
	keys := make(map[string]ed25519.PublicKey, len(publicKeys))
	for keyID, publicKey := range publicKeys {
		if !validIdentifier(keyID) || len(publicKey) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid public key %q", keyID)
		}
		keys[keyID] = bytes.Clone(publicKey)
	}
	return &Ed25519Verifier{publicKeys: keys}, nil
}

func (verifier *Ed25519Verifier) Verify(keyID string, message, signature []byte) error {
	publicKey, exists := verifier.publicKeys[keyID]
	if !exists {
		return ErrUnknownSigningKey
	}
	if len(signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, message, signature) {
		return ErrInvalidSignature
	}
	return nil
}

func Seal(config DeviceConfig, now time.Time, signer Signer) (SignedConfig, error) {
	if err := config.Validate(now); err != nil {
		return SignedConfig{}, err
	}
	if signer == nil || !validIdentifier(signer.KeyID()) {
		return SignedConfig{}, errors.New("invalid configuration signer")
	}
	config = cloneConfig(config)
	signature, err := signer.Sign(signingMessage(config))
	if err != nil {
		return SignedConfig{}, fmt.Errorf("sign configuration: %w", err)
	}
	return SignedConfig{Config: config, KeyID: signer.KeyID(), Signature: bytes.Clone(signature)}, nil
}

func Open(envelope SignedConfig, now time.Time, verifier Verifier) (DeviceConfig, error) {
	if verifier == nil {
		return DeviceConfig{}, errors.New("configuration verifier is required")
	}
	if err := verifier.Verify(envelope.KeyID, signingMessage(envelope.Config), envelope.Signature); err != nil {
		return DeviceConfig{}, fmt.Errorf("verify configuration: %w", err)
	}
	if err := envelope.Config.Validate(now); err != nil {
		return DeviceConfig{}, err
	}
	return cloneConfig(envelope.Config), nil
}

func signingMessage(config DeviceConfig) []byte {
	message := make([]byte, 0, 256)
	message = appendField(message, []byte(configurationDomain))
	message = binary.BigEndian.AppendUint64(message, config.Version)
	message = appendField(message, []byte(config.DeviceID))
	message = appendField(message, []byte(config.NodeID))
	message = appendField(message, []byte(config.Transport))
	message = appendField(message, []byte(config.Endpoint.String()))
	message = binary.BigEndian.AppendUint32(message, uint32(len(config.DNS)))
	for _, resolver := range config.DNS {
		message = appendField(message, []byte(resolver.String()))
	}
	message = binary.BigEndian.AppendUint64(message, uint64(config.IssuedAt.Unix()))
	message = binary.BigEndian.AppendUint64(message, uint64(config.ExpiresAt.Unix()))
	return message
}

func appendField(destination, field []byte) []byte {
	destination = binary.BigEndian.AppendUint32(destination, uint32(len(field)))
	return append(destination, field...)
}

func cloneConfig(config DeviceConfig) DeviceConfig {
	config.DNS = append([]netip.Addr(nil), config.DNS...)
	return config
}
