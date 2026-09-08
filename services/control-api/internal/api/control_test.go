package api_test

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/CH4rnel/CyberiaVPN/services/control-api/internal/api"
	"github.com/CH4rnel/CyberiaVPN/services/control-api/internal/configuration"
)

func TestControlHandlerRoutes(t *testing.T) {
	now := time.Unix(1800000000, 0)
	token, digest := testToken()
	auth, err := api.NewTokenAuthenticator([]api.TokenCredential{{AccountID: "account", TokenSHA256: digest, ExpiresAt: now.Add(time.Hour)}}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := configuration.NewEd25519Verifier(nil)
	if err != nil {
		t.Fatal(err)
	}
	deps := api.ControlDependencies{Authenticator: auth, Enrollment: registeredStore(t, now), Configurations: configuration.NewMemoryStore(), Verifier: verifier, Now: func() time.Time { return now }}
	handler, err := api.NewControlHandler(api.Metadata{Version: "test"}, deps)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		method, path, body string
		authenticated      bool
		status             int
	}{
		{"GET", "/healthz", "", false, 200},
		{"GET", "/api/v1/version", "", false, 200},
		{"GET", "/api/v1/devices/device", "", false, 401},
		{"GET", "/api/v1/devices/device", "", true, 200},
		{"GET", "/api/v1/devices/device/configuration", "", false, 401},
		{"GET", "/api/v1/devices/device/configuration", "", true, 404},
		{"POST", "/api/v1/enrollment/challenges", `{"device_id":"new-device"}`, true, 201},
		{"POST", "/api/v1/devices", `{}`, false, 401},
		{"POST", "/api/v1/devices", `{}`, true, 400},
		{"GET", "/not-an-endpoint", "", true, 404},
	} {
		r := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		r.Header.Set("Content-Type", "application/json")
		if tc.authenticated {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Errorf("%s %s auth=%v: %d %s", tc.method, tc.path, tc.authenticated, w.Code, w.Body.String())
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Error("missing security headers")
		}
	}
	deps.Authenticator = nil
	if _, err := api.NewControlHandler(api.Metadata{}, deps); err == nil {
		t.Fatal("accepted incomplete protected API")
	}
}
