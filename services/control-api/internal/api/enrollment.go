package api

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
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
	mux.HandleFunc("POST /api/v1/enrollment/challenges", func(writer http.ResponseWriter, request *http.Request) {
		account, ok := authenticateAccount(writer, request, auth)
		if !ok {
			return
		}
		var body struct {
			DeviceID string `json:"device_id"`
		}
		if !decodeEnrollmentJSON(writer, request, &body) {
			return
		}
		challenge, err := store.Issue(account, body.DeviceID, now())
		if err != nil {
			writeEnrollmentError(writer, err)
			return
		}
		writeJSON(writer, http.StatusCreated, challenge)
	})
	mux.HandleFunc("POST /api/v1/devices", func(writer http.ResponseWriter, request *http.Request) {
		account, ok := authenticateAccount(writer, request, auth)
		if !ok {
			return
		}
		var body struct {
			DeviceID  string `json:"device_id"`
			PublicKey []byte `json:"public_key"`
			Challenge []byte `json:"challenge"`
			Signature []byte `json:"signature"`
		}
		if !decodeEnrollmentJSON(writer, request, &body) {
			return
		}
		device, err := store.Enroll(identity.EnrollmentRequest{
			AccountID: account, DeviceID: body.DeviceID, PublicKey: body.PublicKey,
			Challenge: body.Challenge, Signature: body.Signature,
		}, now())
		if err != nil {
			writeEnrollmentError(writer, err)
			return
		}
		writeJSON(writer, http.StatusCreated, deviceResponse{DeviceID: device.DeviceID, PublicKey: device.PublicKey, KeyID: device.KeyID})
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

// Enrollment messages contain only identifiers, public keys and proofs.
const maximumEnrollmentBody = 4096

func decodeEnrollmentJSON(writer http.ResponseWriter, request *http.Request, value any) bool {
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeJSON(writer, http.StatusUnsupportedMediaType, errorResponse{Error: "application/json required"})
		return false
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maximumEnrollmentBody)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	err = decoder.Decode(value)
	if err == nil {
		var trailing any
		err = decoder.Decode(&trailing)
		if errors.Is(err, io.EOF) {
			return true
		}
	}
	var oversized *http.MaxBytesError
	if errors.As(err, &oversized) {
		writeJSON(writer, http.StatusRequestEntityTooLarge, errorResponse{Error: "request body too large"})
	} else {
		writeJSON(writer, http.StatusBadRequest, errorResponse{Error: "invalid JSON request"})
	}
	return false
}

func writeEnrollmentError(writer http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, identity.ErrInvalidEnrollment), errors.Is(err, identity.ErrInvalidProof), errors.Is(err, identity.ErrInvalidChallenge):
		writeJSON(writer, http.StatusBadRequest, errorResponse{Error: "invalid enrollment"})
	case errors.Is(err, identity.ErrDeviceExists):
		writeJSON(writer, http.StatusConflict, errorResponse{Error: "device registration conflict"})
	case errors.Is(err, identity.ErrEnrollmentCapacity):
		writeJSON(writer, http.StatusServiceUnavailable, errorResponse{Error: "enrollment capacity reached"})
	default:
		writeJSON(writer, http.StatusInternalServerError, errorResponse{Error: "enrollment failed"})
	}
}
