package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/CH4rnel/CyberiaVPN/services/control-api/internal/api"
)

func TestRuntimeStartsProtectedAPI(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1800000000, 0)
	token := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	digest := sha256.Sum256([]byte(token))
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	handler, runtime, err := newRuntimeHandler(api.Metadata{Version: "test"}, RuntimeConfig{StateDir: dir, Credentials: []api.TokenCredential{{AccountID: "account", TokenSHA256: hex.EncodeToString(digest[:]), ExpiresAt: now.Add(time.Hour)}}, SigningKeys: map[string]string{"key": hex.EncodeToString(private.Public().(ed25519.PublicKey))}}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	for _, tc := range []struct {
		path, token string
		want        int
	}{{"/healthz", "", 200}, {"/api/v1/devices/device", "", 401}, {"/api/v1/devices/device", token, 404}} {
		r := httptest.NewRequest(http.MethodGet, tc.path, nil)
		if tc.token != "" {
			r.Header.Set("Authorization", "Bearer "+tc.token)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Fatalf("%s: %d", tc.path, w.Code)
		}
	}
}

func TestLoadRuntimeConfigRequiresPrivateCompleteJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "runtime.json")
	if err := os.WriteFile(path, []byte(`{"state_dir":"state","credentials":[],"signing_keys":{}}`), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CYBERIA_RUNTIME_CONFIG", path)
	if config, err := loadRuntimeConfig(); err != nil || config.StateDir != "state" {
		t.Fatalf("config=%+v err=%v", config, err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadRuntimeConfig(); err == nil {
		t.Fatal("accepted public config")
	}
}
