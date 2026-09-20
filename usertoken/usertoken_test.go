package usertoken

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
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
	token, err := Sign(key, 42, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	id, err := Verify(&key.PublicKey, token)
	if err != nil || id != 42 {
		t.Fatalf("Verify = (%d, %v), want (42, nil)", id, err)
	}
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
			if id, err := Verify(&key.PublicKey, token); err == nil {
				t.Fatalf("Verify accepted it, returned id %d", id)
			}
		})
	}
}

func TestMiddleware(t *testing.T) {
	key := newKey(t)
	valid, err := Sign(key, 42, time.Minute)
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
