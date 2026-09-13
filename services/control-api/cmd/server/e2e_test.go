package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/CH4rnel/CyberiaVPN/services/control-api/internal/api"
	"github.com/CH4rnel/CyberiaVPN/services/control-api/internal/configuration"
	"github.com/CH4rnel/CyberiaVPN/services/control-api/internal/identity"
)

func TestEnrolledClientReceivesAndPersistsVerifiedConfiguration(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1800000000, 0)
	token := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	digest := sha256.Sum256([]byte(token))
	configPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
	handler, runtime, err := newRuntimeHandler(api.Metadata{}, RuntimeConfig{StateDir: dir, Credentials: []api.TokenCredential{{AccountID: "account", TokenSHA256: hex.EncodeToString(digest[:]), ExpiresAt: now.Add(time.Hour)}}, SigningKeys: map[string]string{"config": hex.EncodeToString(configPrivate.Public().(ed25519.PublicKey))}}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	server := httptest.NewServer(handler)
	defer server.Close()
	request := func(method, path string, body any) *http.Response {
		var input bytes.Buffer
		if body != nil {
			if err := json.NewEncoder(&input).Encode(body); err != nil {
				t.Fatal(err)
			}
		}
		r, err := http.NewRequest(method, server.URL+path, &input)
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Authorization", "Bearer "+token)
		if body != nil {
			r.Header.Set("Content-Type", "application/json")
		}
		response, err := server.Client().Do(r)
		if err != nil {
			t.Fatal(err)
		}
		return response
	}
	response := request(http.MethodPost, "/api/v1/enrollment/challenges", map[string]string{"device_id": "device"})
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("challenge: %s", response.Status)
	}
	var challenge identity.Challenge
	if err := json.NewDecoder(response.Body).Decode(&challenge); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	devicePrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, ed25519.SeedSize))
	proof := identity.EnrollmentRequest{AccountID: "account", DeviceID: "device", PublicKey: devicePrivate.Public().(ed25519.PublicKey), Challenge: challenge.Value}
	proof.Signature = ed25519.Sign(devicePrivate, proof.SigningMessage())
	response = request(http.MethodPost, "/api/v1/devices", map[string]any{"device_id": proof.DeviceID, "public_key": proof.PublicKey, "challenge": proof.Challenge, "signature": proof.Signature})
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("enroll: %s", response.Status)
	}
	response.Body.Close()
	signer, err := configuration.NewEd25519Signer("config", configPrivate)
	if err != nil {
		t.Fatal(err)
	}
	config := configuration.DeviceConfig{Version: 1, DeviceID: "device", NodeID: "node", Transport: configuration.TransportWireGuard, Endpoint: netip.MustParseAddrPort("192.0.2.1:51820"), DNS: []netip.Addr{netip.MustParseAddr("192.0.2.53")}, IssuedAt: now, ExpiresAt: now.Add(time.Hour)}
	envelope, err := configuration.Seal(config, now, signer)
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.configurations.Publish(envelope); err != nil {
		t.Fatal(err)
	}
	response = request(http.MethodGet, "/api/v1/devices/device/configuration", nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("configuration: %s", response.Status)
	}
	var delivered configuration.SignedConfig
	if err := json.NewDecoder(response.Body).Decode(&delivered); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	state, err := configuration.OpenClientState(filepath.Join(dir, "client.json"), "device")
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	verifier, err := configuration.NewEd25519Verifier(map[string]ed25519.PublicKey{"config": configPrivate.Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	if accepted, err := state.Accept(delivered, now, verifier); err != nil || accepted.Version != 1 {
		t.Fatalf("accept=%+v err=%v", accepted, err)
	}
	if _, err := state.Accept(delivered, now, verifier); err == nil {
		t.Fatal("accepted replay")
	}
}
