package api_test

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/CH4rnel/CyberiaVPN/services/control-api/internal/api"
	"github.com/CH4rnel/CyberiaVPN/services/control-api/internal/configuration"
	"github.com/CH4rnel/CyberiaVPN/services/control-api/internal/identity"
)

type configurationReader struct {
	envelope configuration.SignedConfig
	err      error
	calls    int
}

func (reader *configurationReader) Latest(string) (configuration.SignedConfig, error) {
	reader.calls++
	return reader.envelope, reader.err
}

type failedDeviceReader struct{}

func (failedDeviceReader) Device(string, string) (identity.DeviceIdentity, error) {
	return identity.DeviceIdentity{}, errors.New("secret database detail")
}

func TestConfigurationDelivery(t *testing.T) {
	now := time.Unix(1800000000, 123456789).UTC()
	devices := registeredStore(t, now)
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	signer, err := configuration.NewEd25519Signer("test-key", private)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := configuration.NewEd25519Verifier(map[string]ed25519.PublicKey{"test-key": private.Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, account, pathDevice, configDevice      string
		authErr, storeErr                            error
		expired, tampered, unknownKey, deviceFailure bool
		status, reads                                int
	}{
		{name: "owner", account: "account", status: 200, reads: 1},
		{name: "foreign account", account: "other", status: 404},
		{name: "unknown device", account: "account", pathDevice: "missing", status: 404},
		{name: "anonymous", status: 401},
		{name: "bad credentials", account: "account", authErr: errors.New("secret provider detail"), status: 401},
		{name: "missing config", account: "account", storeErr: configuration.ErrConfigNotFound, status: 404, reads: 1},
		{name: "store failure", account: "account", storeErr: errors.New("secret store detail"), status: 500, reads: 1},
		{name: "device failure", account: "account", deviceFailure: true, status: 500},
		{name: "expired", account: "account", expired: true, status: 503, reads: 1},
		{name: "tampered", account: "account", tampered: true, status: 503, reads: 1},
		{name: "unknown key", account: "account", unknownKey: true, status: 503, reads: 1},
		{name: "wrong device config", account: "account", configDevice: "other", status: 503, reads: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			deviceID := tc.configDevice
			if deviceID == "" {
				deviceID = "device"
			}
			config := configuration.DeviceConfig{Version: 2, DeviceID: deviceID, NodeID: "node", Transport: configuration.TransportWireGuard,
				Endpoint: netip.MustParseAddrPort("192.0.2.1:51820"), DNS: []netip.Addr{netip.MustParseAddr("192.0.2.53")},
				IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)}
			envelope, err := configuration.Seal(config, now, signer)
			if err != nil {
				t.Fatal(err)
			}
			if tc.tampered {
				envelope.Config.NodeID = "tampered"
			}
			if tc.unknownKey {
				envelope.KeyID = "unknown"
			}
			reader := &configurationReader{envelope: envelope, err: tc.storeErr}
			var owned api.DeviceReader = devices
			if tc.deviceFailure {
				owned = failedDeviceReader{}
			}
			clock := func() time.Time {
				if tc.expired {
					return config.ExpiresAt
				}
				return now
			}
			handler, err := api.NewConfigurationHandler(accountAuthenticator{account: tc.account, err: tc.authErr}, owned, reader, verifier, clock)
			if err != nil {
				t.Fatal(err)
			}
			pathDevice := tc.pathDevice
			if pathDevice == "" {
				pathDevice = "device"
			}
			request := httptest.NewRequest("GET", "/api/v1/devices/"+pathDevice+"/configuration?account_id=account", nil)
			request.Header.Set("X-Account-ID", "account")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != tc.status {
				t.Fatalf("status = %d, want %d: %s", response.Code, tc.status, response.Body.String())
			}
			if reader.calls != tc.reads {
				t.Fatalf("configuration reads = %d, want %d", reader.calls, tc.reads)
			}
			if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Content-Type") != "application/json" {
				t.Fatal("missing response headers")
			}
			if tc.status == 401 && response.Header().Get("WWW-Authenticate") != "Bearer" {
				t.Fatal("missing authentication challenge")
			}
			if tc.status != 200 {
				if strings.Contains(response.Body.String(), "secret") || strings.Contains(response.Body.String(), "192.0.2.") {
					t.Fatal("leaked private error or configuration")
				}
				return
			}
			var delivered configuration.SignedConfig
			if err := json.Unmarshal(response.Body.Bytes(), &delivered); err != nil {
				t.Fatal(err)
			}
			opened, err := configuration.OpenForDevice(delivered, "device", 1, now, verifier)
			if err != nil {
				t.Fatalf("client rejected delivered envelope: %v", err)
			}
			if !opened.IssuedAt.Equal(config.IssuedAt) || opened.Endpoint != config.Endpoint {
				t.Fatal("changed configuration in transit")
			}
			if _, err := configuration.OpenForDevice(delivered, "device", opened.Version, now, verifier); !errors.Is(err, configuration.ErrStaleVersion) {
				t.Fatalf("client accepted replay: %v", err)
			}
		})
	}
}

func TestConfigurationHandlerRequiresDependencies(t *testing.T) {
	devices := registeredStore(t, time.Unix(1800000000, 0))
	verifier, err := configuration.NewEd25519Verifier(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, missing := range []string{"auth", "devices", "configs", "verifier", "clock"} {
		t.Run(missing, func(t *testing.T) {
			var auth api.AccountAuthenticator = accountAuthenticator{account: "account"}
			var owned api.DeviceReader = devices
			var configs api.ConfigurationReader = &configurationReader{}
			var trusted configuration.Verifier = verifier
			now := time.Now
			switch missing {
			case "auth":
				auth = nil
			case "devices":
				owned = nil
			case "configs":
				configs = nil
			case "verifier":
				trusted = nil
			case "clock":
				now = nil
			}
			if _, err := api.NewConfigurationHandler(auth, owned, configs, trusted, now); err == nil {
				t.Fatal("accepted missing dependency")
			}
		})
	}
}

func TestStoredConfigurationHTTPUpgrade(t *testing.T) {
	now := time.Unix(1800000000, 123456789).UTC()
	devices := registeredStore(t, now)
	configs := configuration.NewMemoryStore()
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	signer, err := configuration.NewEd25519Signer("test-key", private)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := configuration.NewEd25519Verifier(map[string]ed25519.PublicKey{"test-key": private.Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := api.NewConfigurationHandler(accountAuthenticator{account: "account"}, devices, configs, verifier, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	var accepted uint64
	var original configuration.SignedConfig
	for _, version := range []uint64{1, 2} {
		config := configuration.DeviceConfig{Version: version, DeviceID: "device", NodeID: "node", Transport: configuration.TransportWireGuard,
			Endpoint: netip.MustParseAddrPort("192.0.2.1:51820"), DNS: []netip.Addr{netip.MustParseAddr("192.0.2.53")},
			IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)}
		envelope, err := configuration.Seal(config, now, signer)
		if err != nil {
			t.Fatal(err)
		}
		if version == 1 {
			original = envelope
		}
		if err := configs.Publish(envelope); err != nil {
			t.Fatal(err)
		}
		response, err := server.Client().Get(server.URL + "/api/v1/devices/device/configuration")
		if err != nil {
			t.Fatal(err)
		}
		var delivered configuration.SignedConfig
		decodeErr := json.NewDecoder(response.Body).Decode(&delivered)
		closeErr := response.Body.Close()
		if response.StatusCode != 200 || decodeErr != nil || closeErr != nil {
			t.Fatalf("delivery: status=%d decode=%v close=%v", response.StatusCode, decodeErr, closeErr)
		}
		opened, err := configuration.OpenForDevice(delivered, "device", accepted, now, verifier)
		if err != nil || opened.Version != version {
			t.Fatalf("upgrade: version=%d error=%v", opened.Version, err)
		}
		accepted = opened.Version
	}
	if _, err := configuration.OpenForDevice(original, "device", accepted, now, verifier); !errors.Is(err, configuration.ErrStaleVersion) {
		t.Fatalf("accepted rollback after upgrade: %v", err)
	}
}
