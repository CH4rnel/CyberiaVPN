// config-publisher seals and atomically publishes a device configuration into
// the local Control API state directory. It is an operator-only utility.
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/CH4rnel/CyberiaVPN/services/control-api/internal/configuration"
)

func publish(stateDir, inputPath, keyID, privateKeyHex string, now time.Time) error {
	if stateDir == "" || inputPath == "" {
		return errors.New("state directory and input file are required")
	}
	input, err := os.ReadFile(inputPath)
	if err != nil {
		return err
	}
	var config configuration.DeviceConfig
	if err := json.Unmarshal(input, &config); err != nil {
		return err
	}
	privateKey, err := hex.DecodeString(privateKeyHex)
	if err != nil || len(privateKey) != ed25519.PrivateKeySize {
		return errors.New("invalid Ed25519 private key hex")
	}
	signer, err := configuration.NewEd25519Signer(keyID, ed25519.PrivateKey(privateKey))
	if err != nil {
		return err
	}
	envelope, err := configuration.Seal(config, now, signer)
	if err != nil {
		return err
	}
	store, err := configuration.OpenFileStore(filepath.Join(stateDir, "configurations.json"))
	if err != nil {
		return err
	}
	defer store.Close()
	return store.Publish(envelope)
}

func main() {
	stateDir := flag.String("state-dir", "", "private Control API state directory")
	input := flag.String("input", "", "JSON device configuration")
	keyID := flag.String("key-id", "", "signing key identifier")
	privateKey := flag.String("private-key-hex", "", "Ed25519 private key hex")
	flag.Parse()
	if err := publish(*stateDir, *input, *keyID, *privateKey, time.Now()); err != nil {
		fmt.Fprintln(os.Stderr, "publish configuration:", err)
		os.Exit(1)
	}
}
