package api_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/CH4rnel/CyberiaVPN/services/control-api/internal/api"
	"github.com/CH4rnel/CyberiaVPN/services/control-api/internal/identity"
)

type accountAuthenticator struct {
	account string
	err     error
}

func (auth accountAuthenticator) Authenticate(*http.Request) (string, error) {
	return auth.account, auth.err
}

func registeredStore(t *testing.T, now time.Time) *identity.EnrollmentStore {
	t.Helper()
	store, err := identity.NewEnrollmentStore(time.Minute, 10)
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := store.Issue("account", "device", now)
	if err != nil {
		t.Fatal(err)
	}
	request := identity.EnrollmentRequest{AccountID: "account", DeviceID: "device", PublicKey: public, Challenge: challenge.Value}
	request.Signature = ed25519.Sign(private, request.SigningMessage())
	if _, err := store.Enroll(request, now); err != nil {
		t.Fatal(err)
	}
	return store
}

func TestAuthenticatedDeviceLookup(t *testing.T) {
	now := time.Now()
	store := registeredStore(t, now)
	for _, tc := range []struct {
		name, account string
		err           error
		status        int
	}{
		{"owner", "account", nil, 200},
		{"foreign", "other", nil, 404},
		{"empty principal", "", nil, 401},
		{"invalid credential", "account", errors.New("secret provider error"), 401},
	} {
		t.Run(tc.name, func(t *testing.T) {
			handler, err := api.NewEnrollmentHandler(accountAuthenticator{tc.account, tc.err}, store, func() time.Time { return now })
			if err != nil {
				t.Fatal(err)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest("GET", "/api/v1/devices/device", nil))
			if response.Code != tc.status {
				t.Fatalf("status = %d: %s", response.Code, response.Body.String())
			}
			if response.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("missing no-store")
			}
			if tc.status == 401 && response.Header().Get("WWW-Authenticate") != "Bearer" {
				t.Fatal("missing auth challenge")
			}
		})
	}
}

func TestEnrollmentHandlerRequiresDependencies(t *testing.T) {
	store, _ := identity.NewEnrollmentStore(time.Minute, 10)
	if _, err := api.NewEnrollmentHandler(nil, store, time.Now); err == nil {
		t.Fatal("accepted missing authenticator")
	}
	if _, err := api.NewEnrollmentHandler(accountAuthenticator{}, nil, time.Now); err == nil {
		t.Fatal("accepted missing store")
	}
	if _, err := api.NewEnrollmentHandler(accountAuthenticator{}, store, nil); err == nil {
		t.Fatal("accepted missing clock")
	}
}
