package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/CH4rnel/CyberiaVPN/services/control-api/internal/configuration"
	"github.com/CH4rnel/CyberiaVPN/services/control-api/internal/identity"
)

// DeviceReader returns devices only for their authenticated owning account.
type DeviceReader interface {
	Device(accountID, deviceID string) (identity.DeviceIdentity, error)
}

// ConfigurationReader supplies signed public envelopes for registered devices.
// Reading storage does not establish authenticity; delivery verifies each result.
type ConfigurationReader interface {
	Latest(deviceID string) (configuration.SignedConfig, error)
}

// NewConfigurationHandler builds authenticated configuration delivery. Like the
// enrollment handler, it requires an account provider before server integration.
func NewConfigurationHandler(auth AccountAuthenticator, devices DeviceReader, configs ConfigurationReader, verifier configuration.Verifier, now func() time.Time) (http.Handler, error) {
	if auth == nil || devices == nil || configs == nil || verifier == nil || now == nil {
		return nil, errors.New("configuration delivery requires authenticator, device and configuration readers, verifier and clock")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/devices/{deviceID}/configuration", func(writer http.ResponseWriter, request *http.Request) {
		account, ok := authenticateAccount(writer, request, auth)
		if !ok {
			return
		}
		deviceID := request.PathValue("deviceID")
		_, err := devices.Device(account, deviceID)
		if errors.Is(err, identity.ErrDeviceNotFound) {
			writeJSON(writer, http.StatusNotFound, errorResponse{Error: "device not found"})
			return
		}
		if err != nil {
			writeJSON(writer, http.StatusInternalServerError, errorResponse{Error: "device lookup failed"})
			return
		}
		envelope, err := configs.Latest(deviceID)
		if errors.Is(err, configuration.ErrConfigNotFound) {
			writeJSON(writer, http.StatusNotFound, errorResponse{Error: "configuration not found"})
			return
		}
		if err != nil {
			writeJSON(writer, http.StatusInternalServerError, errorResponse{Error: "configuration lookup failed"})
			return
		}
		if _, err := configuration.OpenForDevice(envelope, deviceID, 0, now(), verifier); err != nil {
			writeJSON(writer, http.StatusServiceUnavailable, errorResponse{Error: "configuration unavailable"})
			return
		}
		writeJSON(writer, http.StatusOK, envelope)
	})
	return securityHeaders(mux), nil
}
