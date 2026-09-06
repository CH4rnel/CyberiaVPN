package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/CH4rnel/CyberiaVPN/services/control-api/internal/identity"
)

// AccountAuthenticator verifies credentials and returns the owning account's
// canonical slug. Implementations must respect request cancellation and must
// never trust account IDs supplied in request bodies or unverified headers.
type AccountAuthenticator interface {
	Authenticate(*http.Request) (string, error)
}

// EnrollmentRepository must register identities and consume challenges in one
// atomic operation. A durable adapter must preserve this contract.
type EnrollmentRepository interface {
	Issue(accountID, deviceID string, now time.Time) (identity.Challenge, error)
	Enroll(identity.EnrollmentRequest, time.Time) (identity.DeviceIdentity, error)
	Device(accountID, deviceID string) (identity.DeviceIdentity, error)
}

type deviceResponse struct {
	DeviceID  string `json:"device_id"`
	PublicKey []byte `json:"public_key"`
	KeyID     string `json:"key_id"`
}

// NewEnrollmentHandler builds the authenticated device API. It is not mounted
// by the development server until an account authentication provider is wired.
func NewEnrollmentHandler(auth AccountAuthenticator, store EnrollmentRepository, now func() time.Time) (http.Handler, error) {
	if auth == nil || store == nil || now == nil {
		return nil, errors.New("enrollment requires authenticator, repository and clock")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/devices/{deviceID}", func(writer http.ResponseWriter, request *http.Request) {
		account, ok := authenticateAccount(writer, request, auth)
		if !ok {
			return
		}
		device, err := store.Device(account, request.PathValue("deviceID"))
		if errors.Is(err, identity.ErrDeviceNotFound) {
			writeJSON(writer, http.StatusNotFound, errorResponse{Error: "device not found"})
			return
		}
		if err != nil {
			writeJSON(writer, http.StatusInternalServerError, errorResponse{Error: "device lookup failed"})
			return
		}
		writeJSON(writer, http.StatusOK, deviceResponse{DeviceID: device.DeviceID, PublicKey: device.PublicKey, KeyID: device.KeyID})
	})
	return securityHeaders(mux), nil
}

func authenticateAccount(writer http.ResponseWriter, request *http.Request, auth AccountAuthenticator) (string, bool) {
	account, err := auth.Authenticate(request)
	if err != nil || account == "" {
		writer.Header().Set("WWW-Authenticate", "Bearer")
		writeJSON(writer, http.StatusUnauthorized, errorResponse{Error: "authentication required"})
		return "", false
	}
	return account, true
}
