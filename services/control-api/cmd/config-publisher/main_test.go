package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/CH4rnel/CyberiaVPN/services/control-api/internal/configuration"
)

func TestPublishSealsAndStoresLatestConfiguration(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1800000000, 0)
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	config := configuration.DeviceConfig{Version: 1, DeviceID: "device", NodeID: "node", Transport: configuration.TransportWireGuard, Endpoint: netip.MustParseAddrPort("192.0.2.1:51820"), DNS: []netip.Addr{netip.MustParseAddr("192.0.2.53")}, IssuedAt: now, ExpiresAt: now.Add(time.Hour)}
	input, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, input, 0600); err != nil {
		t.Fatal(err)
	}
	if err := publish(dir, path, "key", hex.EncodeToString(private), now); err != nil {
		t.Fatal(err)
	}
	store, err := configuration.OpenFileStore(filepath.Join(dir, "configurations.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	envelope, err := store.Latest("device")
	if err != nil || envelope.KeyID != "key" {
		t.Fatalf("envelope=%+v err=%v", envelope, err)
	}
	verifier, err := configuration.NewEd25519Verifier(map[string]ed25519.PublicKey{"key": private.Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := configuration.Open(envelope, now, verifier); err != nil {
		t.Fatal(err)
	}
}
