package api

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"
)

var ErrUnauthenticated = errors.New("invalid or expired account credential")

// TokenCredential is an operator-provisioned account credential. Only the SHA-256
// digest of the canonical base64url token is stored, never the bearer secret.
type TokenCredential struct {
	AccountID   string    `json:"account_id"`
	TokenSHA256 string    `json:"token_sha256"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// TokenAuthenticator is a bootstrap provider for a single Control API instance.
// Tokens must be generated from 32 random bytes and delivered over TLS. Rotation
// or revocation replaces the credentials and restarts the service.
type TokenAuthenticator struct {
	credentials map[[32]byte]TokenCredential
	now         func() time.Time
}

var accountSlug = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

func NewTokenAuthenticator(credentials []TokenCredential, now func() time.Time) (*TokenAuthenticator, error) {
	if now == nil || len(credentials) == 0 || len(credentials) > 10000 {
		return nil, errors.New("account credentials and clock required; maximum 10000 credentials")
	}
	auth := &TokenAuthenticator{credentials: make(map[[32]byte]TokenCredential, len(credentials)), now: now}
	at := now()
	for _, credential := range credentials {
		digest, err := hex.DecodeString(credential.TokenSHA256)
		if err != nil || len(digest) != sha256.Size || !accountSlug.MatchString(credential.AccountID) ||
			!credential.ExpiresAt.After(at) || credential.ExpiresAt.After(at.Add(24*time.Hour)) {
			return nil, errors.New("invalid account credential or expiry outside (now, now+24h]")
		}
		key := [32]byte(digest)
		if _, exists := auth.credentials[key]; exists {
			return nil, errors.New("duplicate account token digest")
		}
		auth.credentials[key] = credential
	}
	return auth, nil
}

func (auth *TokenAuthenticator) Authenticate(request *http.Request) (string, error) {
	if err := request.Context().Err(); err != nil {
		return "", err
	}
	values := request.Header.Values("Authorization")
	if len(values) != 1 || len(values[0]) > 128 {
		return "", ErrUnauthenticated
	}
	fields := strings.Fields(values[0])
	if len(fields) != 2 || !strings.EqualFold(fields[0], "Bearer") {
		return "", ErrUnauthenticated
	}
	token, err := base64.RawURLEncoding.Strict().DecodeString(fields[1])
	if err != nil || len(token) != 32 || base64.RawURLEncoding.EncodeToString(token) != fields[1] {
		return "", ErrUnauthenticated
	}
	credential, exists := auth.credentials[sha256.Sum256([]byte(fields[1]))]
	if !exists || !credential.ExpiresAt.After(auth.now()) {
		return "", ErrUnauthenticated
	}
	return credential.AccountID, nil
}
