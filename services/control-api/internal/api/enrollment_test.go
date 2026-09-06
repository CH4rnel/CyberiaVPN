package api_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestEnrollmentChallengeHTTP(t *testing.T) {
	now := time.Unix(1800000000, 0)
	for _, tc := range []struct {
		name, body, contentType, account string
		status                           int
	}{
		{"valid", `{"device_id":"laptop"}`, "application/json; charset=utf-8", "account", 201},
		{"unauthenticated", `{"device_id":"laptop"}`, "application/json", "", 401},
		{"invalid device", `{"device_id":"INVALID"}`, "application/json", "account", 400},
		{"account spoof", `{"device_id":"laptop","account_id":"victim"}`, "application/json", "account", 400},
		{"trailing json", `{"device_id":"laptop"} {}`, "application/json", "account", 400},
		{"invalid json", `{`, "application/json", "account", 400},
		{"null", `null`, "application/json", "account", 400},
		{"wrong type", `{"device_id":1}`, "application/json", "account", 400},
		{"media type", `{}`, "text/plain", "account", 415},
		{"oversized", `{"device_id":"` + strings.Repeat("a", 5000) + `"}`, "application/json", "account", 413},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, _ := identity.NewEnrollmentStore(time.Minute, 1)
			handler, err := api.NewEnrollmentHandler(accountAuthenticator{account: tc.account}, store, func() time.Time { return now })
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest("POST", "/api/v1/enrollment/challenges", strings.NewReader(tc.body))
			request.Header.Set("Content-Type", tc.contentType)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != tc.status {
				t.Fatalf("status = %d: %s", response.Code, response.Body.String())
			}
			if tc.status == 201 {
				var challenge identity.Challenge
				if err := json.Unmarshal(response.Body.Bytes(), &challenge); err != nil {
					t.Fatal(err)
				}
				if err := store.Consume("account", "laptop", challenge.Value, now); err != nil {
					t.Fatalf("account binding: %v", err)
				}
				if !challenge.ExpiresAt.Equal(now.Add(time.Minute)) {
					t.Fatal("wrong expiry")
				}
			}
		})
	}
}

func TestChallengeCapacityHTTP(t *testing.T) {
	store, _ := identity.NewEnrollmentStore(time.Minute, 1)
	handler, err := api.NewEnrollmentHandler(accountAuthenticator{account: "account"}, store, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	for _, status := range []int{201, 503} {
		request := httptest.NewRequest("POST", "/api/v1/enrollment/challenges", strings.NewReader(`{"device_id":"laptop"}`))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != status {
			t.Fatalf("status = %d, want %d", response.Code, status)
		}
	}
}

func postEnrollment(t *testing.T, handler http.Handler, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("POST", path, strings.NewReader(string(encoded)))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func TestHTTPEnrollmentRoundTrip(t *testing.T) {
	now := time.Unix(1800000000, 0)
	store, _ := identity.NewEnrollmentStore(time.Minute, 10)
	handler, err := api.NewEnrollmentHandler(accountAuthenticator{account: "account"}, store, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	issued := postEnrollment(t, handler, "/api/v1/enrollment/challenges", map[string]string{"device_id": "laptop"})
	if issued.Code != 201 {
		t.Fatalf("issue: %s", issued.Body.String())
	}
	var challenge identity.Challenge
	if err := json.Unmarshal(issued.Body.Bytes(), &challenge); err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	proof := identity.EnrollmentRequest{AccountID: "account", DeviceID: "laptop", PublicKey: public, Challenge: challenge.Value}
	signature := ed25519.Sign(private, proof.SigningMessage())
	body := map[string]any{"device_id": "laptop", "public_key": public, "challenge": challenge.Value, "signature": make([]byte, ed25519.SignatureSize)}
	if response := postEnrollment(t, handler, "/api/v1/devices", body); response.Code != 400 {
		t.Fatalf("bad proof: %d %s", response.Code, response.Body.String())
	}
	body["signature"] = signature
	foreign, err := api.NewEnrollmentHandler(accountAuthenticator{account: "other"}, store, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if response := postEnrollment(t, foreign, "/api/v1/devices", body); response.Code != 400 {
		t.Fatalf("cross-account: %d", response.Code)
	}
	body["account_id"] = "victim"
	if response := postEnrollment(t, handler, "/api/v1/devices", body); response.Code != 400 {
		t.Fatalf("account spoof: %d", response.Code)
	}
	delete(body, "account_id")
	registered := postEnrollment(t, handler, "/api/v1/devices", body)
	if registered.Code != 201 {
		t.Fatalf("register: %d %s", registered.Code, registered.Body.String())
	}
	var device struct {
		DeviceID  string `json:"device_id"`
		PublicKey []byte `json:"public_key"`
		KeyID     string `json:"key_id"`
	}
	if err := json.Unmarshal(registered.Body.Bytes(), &device); err != nil {
		t.Fatal(err)
	}
	if device.DeviceID != "laptop" || device.KeyID == "" || string(device.PublicKey) != string(public) {
		t.Fatalf("device: %+v", device)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest("GET", "/api/v1/devices/laptop", nil))
	if response.Code != 200 || response.Body.String() != registered.Body.String() {
		t.Fatalf("lookup: %d %s", response.Code, response.Body.String())
	}
	if response := postEnrollment(t, handler, "/api/v1/devices", body); response.Code != 409 {
		t.Fatalf("replay: %d", response.Code)
	}
}

func TestHTTPEnrollmentExpiryAndAuthentication(t *testing.T) {
	now := time.Now()
	store, _ := identity.NewEnrollmentStore(time.Minute, 10)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := store.Issue("account", "laptop", now)
	if err != nil {
		t.Fatal(err)
	}
	proof := identity.EnrollmentRequest{AccountID: "account", DeviceID: "laptop", PublicKey: public, Challenge: challenge.Value}
	body := map[string]any{"device_id": "laptop", "public_key": public, "challenge": challenge.Value, "signature": ed25519.Sign(private, proof.SigningMessage())}
	for _, tc := range []struct {
		account string
		status  int
	}{{"", 401}, {"account", 400}} {
		handler, err := api.NewEnrollmentHandler(accountAuthenticator{account: tc.account}, store, func() time.Time { return challenge.ExpiresAt })
		if err != nil {
			t.Fatal(err)
		}
		if response := postEnrollment(t, handler, "/api/v1/devices", body); response.Code != tc.status {
			t.Fatalf("status = %d: %s", response.Code, response.Body.String())
		}
	}
	if _, err := store.Device("account", "laptop"); !errors.Is(err, identity.ErrDeviceNotFound) {
		t.Fatalf("persisted failed registration: %v", err)
	}
}
