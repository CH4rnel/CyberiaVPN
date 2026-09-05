package configuration_test

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/CH4rnel/CyberiaVPN/services/control-api/internal/configuration"
)

func TestConfigurationStoreReturnsLatestVersion(t *testing.T) {
	store := configuration.NewMemoryStore()
	first := testEnvelope("laptop-1", 1)
	second := testEnvelope("laptop-1", 2)

	if err := store.Publish(first); err != nil {
		t.Fatalf("publish first config: %v", err)
	}
	if err := store.Publish(second); err != nil {
		t.Fatalf("publish second config: %v", err)
	}
	latest, err := store.Latest("laptop-1")

	if err != nil {
		t.Fatalf("load latest config: %v", err)
	}
	if latest.Config.Version != 2 {
		t.Errorf("version = %d, want 2", latest.Config.Version)
	}
}

func TestConfigurationStoreRejectsRollback(t *testing.T) {
	store := configuration.NewMemoryStore()
	if err := store.Publish(testEnvelope("laptop-1", 2)); err != nil {
		t.Fatalf("publish current config: %v", err)
	}

	err := store.Publish(testEnvelope("laptop-1", 1))

	if !errors.Is(err, configuration.ErrStaleVersion) {
		t.Fatalf("error = %v, want ErrStaleVersion", err)
	}
}

func TestConfigurationStoreDoesNotExposeMutableSlices(t *testing.T) {
	store := configuration.NewMemoryStore()
	envelope := testEnvelope("laptop-1", 1)
	if err := store.Publish(envelope); err != nil {
		t.Fatalf("publish config: %v", err)
	}

	loaded, err := store.Latest("laptop-1")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	loaded.Signature[0] ^= 0xff
	loaded.Config.DNS = nil
	again, err := store.Latest("laptop-1")
	if err != nil {
		t.Fatalf("load config again: %v", err)
	}

	if again.Signature[0] != envelope.Signature[0] || len(again.Config.DNS) == 0 {
		t.Fatal("stored configuration was mutated through a returned value")
	}
}

func TestConfigurationStoreReportsMissingDevice(t *testing.T) {
	_, err := configuration.NewMemoryStore().Latest("unknown-device")

	if !errors.Is(err, configuration.ErrConfigNotFound) {
		t.Fatalf("error = %v, want ErrConfigNotFound", err)
	}
}

func testEnvelope(deviceID string, version uint64) configuration.SignedConfig {
	config := validConfig(testNow())
	config.DeviceID = deviceID
	config.Version = version
	return configuration.SignedConfig{
		Config:    config,
		KeyID:     "config-key-1",
		Signature: []byte{1, 2, 3},
	}
}

func testNow() time.Time {
	return time.Unix(1_788_563_400, 0).UTC()
}

func TestZeroValueConfigurationStore(t *testing.T) {
	var store configuration.MemoryStore
	if _, err := store.Latest("laptop-1"); !errors.Is(err, configuration.ErrConfigNotFound) {
		t.Fatalf("empty lookup: %v", err)
	}
	if err := store.Publish(testEnvelope("laptop-1", 1)); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if err := store.Publish(testEnvelope("laptop-1", 1)); !errors.Is(err, configuration.ErrStaleVersion) {
		t.Fatalf("duplicate version: %v", err)
	}
	latest, err := store.Latest("laptop-1")
	if err != nil || latest.Config.Version != 1 {
		t.Fatalf("latest = %+v, error = %v", latest, err)
	}
}

func TestZeroValueStoreSerializesConcurrentVersions(t *testing.T) {
	var store configuration.MemoryStore
	const writers = 32
	var group sync.WaitGroup
	for version := uint64(1); version <= writers; version++ {
		group.Add(1)
		go func() {
			defer group.Done()
			err := store.Publish(testEnvelope("laptop-1", version))
			if err != nil && !errors.Is(err, configuration.ErrStaleVersion) {
				t.Errorf("publish version %d: %v", version, err)
			}
		}()
	}
	group.Wait()
	latest, err := store.Latest("laptop-1")
	if err != nil || latest.Config.Version != writers {
		t.Fatalf("latest version = %d, error = %v", latest.Config.Version, err)
	}
}
