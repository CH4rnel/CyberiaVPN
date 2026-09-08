package api_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/CH4rnel/CyberiaVPN/services/control-api/internal/api"
)

func testToken() (string, string) {
	token := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	digest := sha256.Sum256([]byte(token))
	return token, hex.EncodeToString(digest[:])
}

func TestTokenAuthentication(t *testing.T) {
	now := time.Unix(1800000000, 0)
	token, digest := testToken()
	credentials := []api.TokenCredential{{AccountID: "account", TokenSHA256: digest, ExpiresAt: now.Add(time.Hour)}}
	auth, err := api.NewTokenAuthenticator(credentials, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	credentials[0].AccountID = "changed"
	for _, tc := range []struct {
		name      string
		headers   []string
		cancelled bool
		ok        bool
	}{
		{"valid", []string{"Bearer " + token}, false, true},
		{"case insensitive scheme", []string{"bearer " + token}, false, true},
		{"missing", nil, false, false},
		{"wrong scheme", []string{"Basic " + token}, false, false},
		{"wrong token", []string{"Bearer " + strings.Repeat("b", 43)}, false, false},
		{"duplicate", []string{"Bearer " + token, "Bearer " + token}, false, false},
		{"extra field", []string{"Bearer " + token + " extra"}, false, false},
		{"cancelled", []string{"Bearer " + token}, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/?access_token="+token, nil)
			for _, header := range tc.headers {
				r.Header.Add("Authorization", header)
			}
			if tc.cancelled {
				ctx, cancel := context.WithCancel(r.Context())
				cancel()
				r = r.WithContext(ctx)
			}
			account, err := auth.Authenticate(r)
			if tc.ok {
				if err != nil || account != "account" {
					t.Fatalf("account=%q err=%v", account, err)
				}
				return
			}
			if err == nil || account != "" {
				t.Fatalf("accepted invalid credential: %q %v", account, err)
			}
		})
	}
	now = now.Add(time.Hour)
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	if _, err := auth.Authenticate(r); !errors.Is(err, api.ErrUnauthenticated) {
		t.Fatalf("accepted at expiration: %v", err)
	}
}

func TestTokenCredentialValidation(t *testing.T) {
	now := time.Unix(1800000000, 0)
	_, digest := testToken()
	valid := api.TokenCredential{AccountID: "account", TokenSHA256: digest, ExpiresAt: now.Add(time.Hour)}
	for _, change := range []func(*api.TokenCredential){
		func(c *api.TokenCredential) { c.AccountID = "INVALID" },
		func(c *api.TokenCredential) { c.AccountID = "" },
		func(c *api.TokenCredential) { c.TokenSHA256 = "bad" },
		func(c *api.TokenCredential) { c.ExpiresAt = now },
		func(c *api.TokenCredential) { c.ExpiresAt = now.Add(25 * time.Hour) },
	} {
		credential := valid
		change(&credential)
		if _, err := api.NewTokenAuthenticator([]api.TokenCredential{credential}, func() time.Time { return now }); err == nil {
			t.Fatal("accepted invalid credential")
		}
	}
	if _, err := api.NewTokenAuthenticator([]api.TokenCredential{valid, valid}, func() time.Time { return now }); err == nil {
		t.Fatal("accepted duplicate token")
	}
	if _, err := api.NewTokenAuthenticator(nil, time.Now); err == nil {
		t.Fatal("accepted empty credentials")
	}
	if _, err := api.NewTokenAuthenticator([]api.TokenCredential{valid}, nil); err == nil {
		t.Fatal("accepted missing clock")
	}
}
