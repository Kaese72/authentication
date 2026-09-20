// Package usertoken is the single definition of the authentication service's
// `use` token: how it is signed, how it is verified, and what claims it
// carries. It is deliberately a public package of the authentication module
// (not under internal/) so that other services can import it instead of
// re-implementing the token format.
//
// A `use` token is an RS256 JWT whose only identifying claim is "id", the ID
// of the authenticated user. Services verify it locally against the
// authentication service's RSA public key; nothing here calls the
// authentication service.
//
// Deliberately only depends on the JWT library and huemie-lib's error
// formatting, so importing it does not pull the authentication service's own
// dependencies (database driver, APM, ...) into a consumer.
package usertoken

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Kaese72/huemie-lib/liberrors"
	"github.com/golang-jwt/jwt/v5"
)

// ClaimID is the name of the claim holding the authenticated user's ID.
const ClaimID = "id"

// Sign issues a use token for userID, valid for expiry. Only the
// authentication service, which holds the private key, should call this.
func Sign(privateKey *rsa.PrivateKey, userID int64, expiry time.Duration) (string, error) {
	claims := jwt.MapClaims{
		ClaimID: userID,
		"exp":   time.Now().Add(expiry).Unix(),
		"iat":   time.Now().Unix(),
	}
	return jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(privateKey)
}

// Verify checks tokenString's RS256 signature and expiry against publicKey
// and returns the user ID it was issued for. A validly signed token without a
// usable (positive, numeric) id claim is rejected: every use token the
// authentication service issues has one, so its absence means the token is
// not a use token.
func Verify(publicKey *rsa.PublicKey, tokenString string) (int64, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})
	if err != nil {
		return 0, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return 0, errors.New("invalid token")
	}
	id, ok := claims[ClaimID].(float64)
	if !ok || id < 1 {
		return 0, errors.New("invalid id claim")
	}
	return int64(id), nil
}

type userIDContextKey struct{}

// UserID returns the authenticated caller's user ID, as placed in the request
// context by Middleware. It returns false if the request did not pass through
// Middleware, or matched one of its skipped prefixes.
func UserID(ctx context.Context) (int64, bool) {
	id, ok := ctx.Value(userIDContextKey{}).(int64)
	return id, ok
}

// Middleware returns an HTTP middleware that requires a valid use token as a
// bearer token and makes the caller's user ID available through UserID.
// Requests whose path starts with any entry in skipPrefixes bypass
// authentication entirely (and so have no user ID).
//
// The returned type is func(http.Handler) http.Handler, which is directly
// assignable to gorilla/mux's MiddlewareFunc without an explicit cast.
func Middleware(publicKey *rsa.PublicKey, skipPrefixes ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for _, prefix := range skipPrefixes {
				if strings.HasPrefix(r.URL.Path, prefix) {
					next.ServeHTTP(w, r)
					return
				}
			}
			authHeader := r.Header.Get("Authorization")
			if !strings.HasPrefix(authHeader, "Bearer ") {
				liberrors.NewApiError(liberrors.Unauthorized, errors.New("missing bearer token")).WriteHTTP(w)
				return
			}
			userID, err := Verify(publicKey, strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer ")))
			if err != nil {
				liberrors.NewApiError(liberrors.Unauthorized, errors.New("invalid or expired token")).WriteHTTP(w)
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), userIDContextKey{}, userID)))
		})
	}
}
