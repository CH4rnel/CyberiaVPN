package configuration_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/CH4rnel/CyberiaVPN/services/control-api/internal/configuration"
)

func TestSignedConfigurationUsesStablePublicJSONFields(t *testing.T) {
	envelope := testEnvelope("laptop-1", 1)
	envelope.Config = validConfig(testNow())
	data, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	encoded := string(data)
	for _, field := range []string{"\"config\"", "\"key_id\"", "\"signature\"", "\"peer_public_key\"", "\"tunnel_addresses\"", "\"allowed_ips\"", "\"persistent_keepalive_seconds\""} {
		if !strings.Contains(encoded, field) {
			t.Fatalf("missing %s in %s", field, encoded)
		}
	}
	if strings.Contains(encoded, "Private") || strings.Contains(encoded, "private") {
		t.Fatalf("private material leaked: %s", encoded)
	}
	var decoded configuration.SignedConfig
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Config.WireGuard.MTU != 1420 || len(decoded.Config.WireGuard.PeerPublicKey) != 32 {
		t.Fatalf("decoded=%+v", decoded.Config.WireGuard)
	}
}
