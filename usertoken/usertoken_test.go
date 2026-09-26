package usertoken

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func newKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// rawToken signs arbitrary claims, bypassing Sign, to build tokens Sign would
// never produce.
func rawToken(t *testing.T, method jwt.SigningMethod, key any, claims jwt.MapClaims) string {
	t.Helper()
	s, err := jwt.NewWithClaims(method, claims).SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSignVerifyRoundTrip(t *testing.T) {
	key := newKey(t)
	token, err := Sign(key, 42, time.Minute, Permissions{})
	if err != nil {
		t.Fatal(err)
	}
	id, permissions, err := Verify(&key.PublicKey, token)
	if err != nil || id != 42 {
		t.Fatalf("Verify = (%d, %v), want (42, nil)", id, err)
	}
	if permissions.Admin() || permissions.HasView(ResourceDevices) {
		t.Fatalf("Verify returned non-empty permissions for a token signed with none: %+v", permissions)
	}
}

func TestSignVerifyRoundTripWithPermissions(t *testing.T) {
	key := newKey(t)

	t.Run("admin", func(t *testing.T) {
		token, err := Sign(key, 1, time.Minute, AdminPermissions())
		if err != nil {
			t.Fatal(err)
		}
		_, permissions, err := Verify(&key.PublicKey, token)
		if err != nil {
			t.Fatal(err)
		}
		if !permissions.Admin() || !permissions.HasView(ResourceDevices) || !permissions.HasModify(ResourceAutomationRules) {
			t.Fatalf("admin permissions did not round-trip: %+v", permissions)
		}
	})

	t.Run("resource grants, modify implies view", func(t *testing.T) {
		token, err := Sign(key, 1, time.Minute, NewPermissions(map[string]ResourceGrant{
			ResourceDevices:         {View: accessAll},
			ResourceAutomationRules: {Modify: accessAll},
		}))
		if err != nil {
			t.Fatal(err)
		}
		_, permissions, err := Verify(&key.PublicKey, token)
		if err != nil {
			t.Fatal(err)
		}
		if permissions.Admin() {
			t.Fatal("expected non-admin permissions")
		}
		if !permissions.HasView(ResourceDevices) || permissions.HasModify(ResourceDevices) {
			t.Fatalf("devices: HasView/HasModify = (%v, %v), want (true, false)", permissions.HasView(ResourceDevices), permissions.HasModify(ResourceDevices))
		}
		if !permissions.HasView(ResourceAutomationRules) || !permissions.HasModify(ResourceAutomationRules) {
			t.Fatalf("automation rules: HasView/HasModify = (%v, %v), want (true, true)", permissions.HasView(ResourceAutomationRules), permissions.HasModify(ResourceAutomationRules))
		}
		if permissions.HasView(ResourceUsers) {
			t.Fatal("expected no access to a resource with no grant")
		}
	})
}

func TestVerifyRejects(t *testing.T) {
	key, other := newKey(t), newKey(t)
	exp := time.Now().Add(time.Minute).Unix()

	tests := map[string]string{
		"wrong key":      rawToken(t, jwt.SigningMethodRS256, other, jwt.MapClaims{ClaimID: 1, "exp": exp}),
		"expired":        rawToken(t, jwt.SigningMethodRS256, key, jwt.MapClaims{ClaimID: 1, "exp": time.Now().Add(-time.Minute).Unix()}),
		"no id":          rawToken(t, jwt.SigningMethodRS256, key, jwt.MapClaims{"sub": "x", "exp": exp}),
		"non-numeric id": rawToken(t, jwt.SigningMethodRS256, key, jwt.MapClaims{ClaimID: "abc", "exp": exp}),
		"zero id":        rawToken(t, jwt.SigningMethodRS256, key, jwt.MapClaims{ClaimID: 0, "exp": exp}),
		"negative id":    rawToken(t, jwt.SigningMethodRS256, key, jwt.MapClaims{ClaimID: -5, "exp": exp}),
		"HMAC (refresh)": rawToken(t, jwt.SigningMethodHS256, []byte("secret"), jwt.MapClaims{ClaimID: 1, "exp": exp}),
		"not a token":    "nonsense",
		"empty":          "",
	}
	for name, token := range tests {
		t.Run(name, func(t *testing.T) {
			if id, _, err := Verify(&key.PublicKey, token); err == nil {
				t.Fatalf("Verify accepted it, returned id %d", id)
			}
		})
	}
}

func TestMiddleware(t *testing.T) {
	key := newKey(t)
	valid, err := Sign(key, 42, time.Minute, AdminPermissions())
	if err != nil {
		t.Fatal(err)
	}
	noID := rawToken(t, jwt.SigningMethodRS256, key, jwt.MapClaims{"sub": "x", "exp": time.Now().Add(time.Minute).Unix()})

	tests := []struct {
		name       string
		path       string
		auth       string
		wantStatus int
		wantID     int64
		wantIDOk   bool
	}{
		{"valid token exposes id", "/x", "Bearer " + valid, http.StatusOK, 42, true},
		{"skipped prefix passes with no id", "/docs/x", "", http.StatusOK, 0, false},
		{"skipped prefix ignores a bad token", "/docs/x", "Bearer nonsense", http.StatusOK, 0, false},
		{"missing header", "/x", "", http.StatusUnauthorized, 0, false},
		{"not a bearer header", "/x", "Basic abc", http.StatusUnauthorized, 0, false},
		{"garbage token", "/x", "Bearer nonsense", http.StatusUnauthorized, 0, false},
		{"validly signed but no id", "/x", "Bearer " + noID, http.StatusUnauthorized, 0, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var (
				called bool
				id     int64
				ok     bool
			)
			h := Middleware(&key.PublicKey, "/docs")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				id, ok = UserID(r.Context())
			}))
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			if tc.auth != "" {
				req.Header.Set("Authorization", tc.auth)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
			if called != (tc.wantStatus == http.StatusOK) {
				t.Fatalf("handler called = %v with status %d", called, rec.Code)
			}
			if id != tc.wantID || ok != tc.wantIDOk {
				t.Fatalf("UserID = (%d, %v), want (%d, %v)", id, ok, tc.wantID, tc.wantIDOk)
			}
		})
	}
}

func writePEM(t *testing.T, blockType string, der []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadPublicKeyFromFile(t *testing.T) {
	key := newKey(t)
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("loads a PKIX RSA key that verifies tokens", func(t *testing.T) {
		pub, err := LoadPublicKeyFromFile(writePEM(t, "PUBLIC KEY", der))
		if err != nil {
			t.Fatal(err)
		}
		token, err := Sign(key, 7, time.Minute, Permissions{})
		if err != nil {
			t.Fatal(err)
		}
		if id, _, err := Verify(pub, token); err != nil || id != 7 {
			t.Fatalf("Verify with loaded key = (%d, %v), want (7, nil)", id, err)
		}
	})

	t.Run("missing file", func(t *testing.T) {
		if _, err := LoadPublicKeyFromFile(filepath.Join(t.TempDir(), "nope.pem")); err == nil {
			t.Fatal("expected an error")
		}
	})

	t.Run("no PEM block", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "key.pem")
		if err := os.WriteFile(path, []byte("not pem"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadPublicKeyFromFile(path); err == nil {
			t.Fatal("expected an error")
		}
	})

	t.Run("PEM that is not a public key", func(t *testing.T) {
		if _, err := LoadPublicKeyFromFile(writePEM(t, "PUBLIC KEY", []byte("garbage"))); err == nil {
			t.Fatal("expected an error")
		}
	})

	t.Run("non-RSA public key", func(t *testing.T) {
		ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		ecDER, err := x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := LoadPublicKeyFromFile(writePEM(t, "PUBLIC KEY", ecDER)); err == nil {
			t.Fatal("expected an error for a non-RSA key")
		}
	})
}
