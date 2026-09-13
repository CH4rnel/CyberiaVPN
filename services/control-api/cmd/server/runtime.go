package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/CH4rnel/CyberiaVPN/services/control-api/internal/api"
	"github.com/CH4rnel/CyberiaVPN/services/control-api/internal/configuration"
	"github.com/CH4rnel/CyberiaVPN/services/control-api/internal/identity"
)

// RuntimeConfig contains references to private state and operator credentials.
// It deliberately accepts token digests and public signing keys only.
type RuntimeConfig struct {
	StateDir    string
	Credentials []api.TokenCredential
	SigningKeys map[string]string
}

type runtime struct {
	enrollment     *identity.FileEnrollmentStore
	configurations *configuration.FileStore
}

func (runtime *runtime) Close() error {
	first := runtime.enrollment.Close()
	second := runtime.configurations.Close()
	if first != nil {
		return first
	}
	return second
}

func newRuntimeHandler(metadata api.Metadata, config RuntimeConfig, now func() time.Time) (http.Handler, *runtime, error) {
	if config.StateDir == "" || now == nil {
		return nil, nil, errors.New("private state directory and clock required")
	}
	if err := os.MkdirAll(config.StateDir, 0700); err != nil {
		return nil, nil, err
	}
	if err := os.Chmod(config.StateDir, 0700); err != nil {
		return nil, nil, err
	}
	auth, err := api.NewTokenAuthenticator(config.Credentials, now)
	if err != nil {
		return nil, nil, err
	}
	keys := make(map[string]ed25519.PublicKey, len(config.SigningKeys))
	for id, encoded := range config.SigningKeys {
		raw, err := hex.DecodeString(encoded)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, nil, errors.New("invalid configuration signing public key")
		}
		keys[id] = ed25519.PublicKey(raw)
	}
	verifier, err := configuration.NewEd25519Verifier(keys)
	if err != nil {
		return nil, nil, err
	}
	enrollment, err := identity.OpenFileEnrollmentStore(filepath.Join(config.StateDir, "enrollment.json"), time.Minute, 10000)
	if err != nil {
		return nil, nil, err
	}
	configs, err := configuration.OpenFileStore(filepath.Join(config.StateDir, "configurations.json"))
	if err != nil {
		enrollment.Close()
		return nil, nil, err
	}
	handler, err := api.NewControlHandler(metadata, api.ControlDependencies{Authenticator: auth, Enrollment: enrollment, Configurations: configs, Verifier: verifier, Now: now})
	if err != nil {
		configs.Close()
		enrollment.Close()
		return nil, nil, err
	}
	return handler, &runtime{enrollment: enrollment, configurations: configs}, nil
}
