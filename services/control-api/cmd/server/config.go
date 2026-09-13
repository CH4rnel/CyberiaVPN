package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"

	"github.com/CH4rnel/CyberiaVPN/services/control-api/internal/api"
)

const maximumRuntimeConfig = 1 << 20

func loadRuntimeConfig() (RuntimeConfig, error) {
	path := os.Getenv("CYBERIA_RUNTIME_CONFIG")
	if path == "" {
		return RuntimeConfig{}, errors.New("CYBERIA_RUNTIME_CONFIG is required")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return RuntimeConfig{}, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > maximumRuntimeConfig {
		return RuntimeConfig{}, errors.New("runtime configuration must be a private regular file below 1 MiB")
	}
	input, err := os.Open(path)
	if err != nil {
		return RuntimeConfig{}, err
	}
	defer input.Close()
	data, err := io.ReadAll(io.LimitReader(input, maximumRuntimeConfig+1))
	if err != nil {
		return RuntimeConfig{}, err
	}
	if len(data) > maximumRuntimeConfig {
		return RuntimeConfig{}, errors.New("runtime configuration exceeds 1 MiB")
	}
	var config struct {
		StateDir    string                `json:"state_dir"`
		Credentials []api.TokenCredential `json:"credentials"`
		SigningKeys map[string]string     `json:"signing_keys"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return RuntimeConfig{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return RuntimeConfig{}, errors.New("runtime configuration has trailing data")
	}
	return RuntimeConfig{StateDir: config.StateDir, Credentials: config.Credentials, SigningKeys: config.SigningKeys}, nil
}
