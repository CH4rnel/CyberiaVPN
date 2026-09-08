package api

import (
	"net/http"
	"time"

	"github.com/CH4rnel/CyberiaVPN/services/control-api/internal/configuration"
)

// ControlDependencies makes all protected API trust boundaries explicit.
type ControlDependencies struct {
	Authenticator  AccountAuthenticator
	Enrollment     EnrollmentRepository
	Configurations ConfigurationReader
	Verifier       configuration.Verifier
	Now            func() time.Time
}

// NewControlHandler exposes public diagnostics and the authenticated M1 API.
// Missing dependencies fail construction; there is no anonymous fallback.
func NewControlHandler(metadata Metadata, dependencies ControlDependencies) (http.Handler, error) {
	enrollment, err := NewEnrollmentHandler(dependencies.Authenticator, dependencies.Enrollment, dependencies.Now)
	if err != nil {
		return nil, err
	}
	configs, err := NewConfigurationHandler(dependencies.Authenticator, dependencies.Enrollment, dependencies.Configurations, dependencies.Verifier, dependencies.Now)
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.Handle("GET /api/v1/devices/{deviceID}/configuration", configs)
	mux.Handle("GET /api/v1/devices/{deviceID}", enrollment)
	mux.Handle("POST /api/v1/devices", enrollment)
	mux.Handle("POST /api/v1/enrollment/challenges", enrollment)
	mux.Handle("/", NewHandler(metadata))
	return securityHeaders(mux), nil
}
