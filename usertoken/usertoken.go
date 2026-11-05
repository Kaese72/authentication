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
// The package also defines API tokens (see apitoken.go): long-lived, opaque
// tokens a user provisions for themselves, which - unlike use tokens - are
// looked up in the authentication service on use (see introspect.go). A
// service only accepts them if it opts in with AcceptAPITokens.
//
// Deliberately only depends on the JWT library and huemie-lib's error
// formatting, so importing it does not pull the authentication service's own
// dependencies (database driver, APM, ...) into a consumer.
package usertoken

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Kaese72/huemie-lib/liberrors"
	"github.com/golang-jwt/jwt/v5"
)

// ClaimID is the name of the claim holding the authenticated user's ID.
const ClaimID = "id"

// LoadPublicKeyFromFile reads the authentication service's PKIX PEM-encoded
// RSA public key from disk, for use with Verify and Middleware.
func LoadPublicKeyFromFile(path string) (*rsa.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read public key file: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key at %s is not an RSA public key", path)
	}
	return rsaPub, nil
}

// Sign issues a use token for userID with the given permissions, valid for
// expiry. Only the authentication service, which holds the private key,
// should call this.
func Sign(privateKey *rsa.PrivateKey, userID int64, expiry time.Duration, permissions Permissions, opts ...SignOption) (string, error) {
	claims := jwt.MapClaims{
		ClaimID: userID,
		"exp":   time.Now().Add(expiry).Unix(),
		"iat":   time.Now().Unix(),
	}
	if raw := permissions.toRaw(); len(raw) > 0 {
		claims[ClaimPermissions] = raw
	}
	for _, opt := range opts {
		opt(claims)
	}
	return jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(privateKey)
}

// SignOption adds an optional claim to a token issued by Sign.
type SignOption func(jwt.MapClaims)

// WithLoginMethod records how the session the token belongs to was
// established, as the lm claim. See LoginMethod.
func WithLoginMethod(method LoginMethod) SignOption {
	return func(claims jwt.MapClaims) {
		if method.signable() {
			claims[ClaimLoginMethod] = string(method)
		}
	}
}

// VerifiedToken is what VerifyToken extracts from a valid use token.
type VerifiedToken struct {
	UserID      int64
	Permissions Permissions
	// LoginMethod is LoginMethodUnknown for tokens issued without one (by an
	// older authentication service, say) - never assume it means "local".
	LoginMethod LoginMethod
}

// Verify checks tokenString's RS256 signature and expiry against publicKey
// and returns the user ID it was issued for, along with its permissions. A
// validly signed token without a usable (positive, numeric) id claim is
// rejected: every use token the authentication service issues has one, so its
// absence means the token is not a use token. A token with no hp claim, or an
// unparseable one, carries the zero Permissions (no access).
func Verify(publicKey *rsa.PublicKey, tokenString string) (int64, Permissions, error) {
	verified, err := VerifyToken(publicKey, tokenString)
	if err != nil {
		return 0, Permissions{}, err
	}
	return verified.UserID, verified.Permissions, nil
}

// VerifyToken is Verify, additionally returning the token's login method.
func VerifyToken(publicKey *rsa.PublicKey, tokenString string) (VerifiedToken, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})
	if err != nil {
		return VerifiedToken{}, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return VerifiedToken{}, errors.New("invalid token")
	}
	id, ok := claims[ClaimID].(float64)
	if !ok || id < 1 {
		return VerifiedToken{}, errors.New("invalid id claim")
	}
	permissions := Permissions{}
	if raw, ok := claims[ClaimPermissions].(map[string]interface{}); ok {
		permissions = permissionsFromRaw(raw)
	}
	method := LoginMethodUnknown
	if raw, ok := claims[ClaimLoginMethod].(string); ok && LoginMethod(raw).signable() {
		method = LoginMethod(raw)
	}
	return VerifiedToken{UserID: int64(id), Permissions: permissions, LoginMethod: method}, nil
}

// authContext is what Middleware places in the request context: the
// authenticated caller's user ID, permissions and how they authenticated,
// together so all come from the same verified credential.
type authContext struct {
	userID      int64
	permissions Permissions
	method      LoginMethod
}

type userIDContextKey struct{}

// UserID returns the authenticated caller's user ID, as placed in the request
// context by Middleware. It returns false if the request did not pass through
// Middleware, or matched one of its skipped prefixes.
func UserID(ctx context.Context) (int64, bool) {
	auth, ok := ctx.Value(userIDContextKey{}).(authContext)
	return auth.userID, ok
}

// PermissionsFromContext returns the authenticated caller's permissions, as
// placed in the request context by Middleware. It returns false if the
// request did not pass through Middleware, or matched one of its skipped
// prefixes - callers must treat that the same as "no access", not bypass the
// check.
func PermissionsFromContext(ctx context.Context) (Permissions, bool) {
	auth, ok := ctx.Value(userIDContextKey{}).(authContext)
	return auth.permissions, ok
}

// LoginMethodFromContext returns how the authenticated caller authenticated,
// as placed in the request context by Middleware: LoginMethodAPIToken for an
// API token, otherwise the use token's own lm claim. It returns false if the
// request did not pass through Middleware.
func LoginMethodFromContext(ctx context.Context) (LoginMethod, bool) {
	auth, ok := ctx.Value(userIDContextKey{}).(authContext)
	return auth.method, ok
}

// IsAPITokenRequest reports whether the caller authenticated with an API
// token. A handler in a service that accepts API tokens can use it to refuse
// them for a single operation, as a finer-grained alternative to
// RejectAPITokensFor.
func IsAPITokenRequest(ctx context.Context) bool {
	method, _ := LoginMethodFromContext(ctx)
	return method == LoginMethodAPIToken
}

// ContextWithAuth returns a copy of ctx carrying userID and permissions
// exactly as Middleware would have placed them, for consuming services' unit
// tests that call a handler directly (bypassing HTTP and Middleware) and need
// UserID / PermissionsFromContext to report as if a valid token had been
// presented. Not for production request handling - that path only ever goes
// through Middleware.
func ContextWithAuth(ctx context.Context, userID int64, permissions Permissions) context.Context {
	return ContextWithLogin(ctx, userID, permissions, LoginMethodUnknown)
}

// ContextWithLogin is ContextWithAuth, additionally setting the login method
// LoginMethodFromContext reports. For tests only, like ContextWithAuth.
func ContextWithLogin(ctx context.Context, userID int64, permissions Permissions, method LoginMethod) context.Context {
	return context.WithValue(ctx, userIDContextKey{}, authContext{userID: userID, permissions: permissions, method: method})
}

// MiddlewareOption configures NewMiddleware.
type MiddlewareOption func(*middlewareConfig)

type middlewareConfig struct {
	skipPrefixes      []string
	introspector      APITokenIntrospector
	rejectAPIPrefixes []string
}

// SkipPrefixes makes requests whose path starts with any of prefixes bypass
// authentication entirely (and so have no user ID).
func SkipPrefixes(prefixes ...string) MiddlewareOption {
	return func(c *middlewareConfig) { c.skipPrefixes = append(c.skipPrefixes, prefixes...) }
}

// AcceptAPITokens makes the middleware accept API tokens as well as use
// tokens, looking each one up through introspector (normally an
// *Introspector). Without this option, API tokens are refused.
func AcceptAPITokens(introspector APITokenIntrospector) MiddlewareOption {
	return func(c *middlewareConfig) { c.introspector = introspector }
}

// RejectAPITokensFor is the override for a service that accepts API tokens
// but must not accept them on some routes: requests whose path starts with
// any of prefixes are refused when they carry an API token, while use tokens
// keep working there. Has no effect without AcceptAPITokens, since API tokens
// are then refused everywhere anyway. For a decision that depends on more
// than the path, see IsAPITokenRequest.
func RejectAPITokensFor(prefixes ...string) MiddlewareOption {
	return func(c *middlewareConfig) { c.rejectAPIPrefixes = append(c.rejectAPIPrefixes, prefixes...) }
}

func hasAnyPrefix(path string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// Middleware returns an HTTP middleware that requires a valid use token as a
// bearer token and makes the caller's user ID available through UserID.
// Requests whose path starts with any entry in skipPrefixes bypass
// authentication entirely (and so have no user ID). API tokens are refused;
// use NewMiddleware with AcceptAPITokens to accept them.
//
// The returned type is func(http.Handler) http.Handler, which is directly
// assignable to gorilla/mux's MiddlewareFunc without an explicit cast.
func Middleware(publicKey *rsa.PublicKey, skipPrefixes ...string) func(http.Handler) http.Handler {
	return NewMiddleware(publicKey, SkipPrefixes(skipPrefixes...))
}

// NewMiddleware is Middleware, configured through options. API tokens are
// only accepted with AcceptAPITokens: a service that never passes it - like
// the authentication service itself - refuses them everywhere.
func NewMiddleware(publicKey *rsa.PublicKey, opts ...MiddlewareOption) func(http.Handler) http.Handler {
	var conf middlewareConfig
	for _, opt := range opts {
		opt(&conf)
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if hasAnyPrefix(r.URL.Path, conf.skipPrefixes) {
				next.ServeHTTP(w, r)
				return
			}
			authHeader := r.Header.Get("Authorization")
			if !strings.HasPrefix(authHeader, "Bearer ") {
				liberrors.NewApiError(liberrors.Unauthorized, errors.New("missing bearer token")).WriteHTTP(w)
				return
			}
			tokenString := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))

			var auth authContext
			if IsAPIToken(tokenString) {
				if conf.introspector == nil || hasAnyPrefix(r.URL.Path, conf.rejectAPIPrefixes) {
					liberrors.NewApiError(liberrors.ApiReason(http.StatusForbidden), errors.New("API tokens are not accepted here")).WriteHTTP(w)
					return
				}
				userID, permissions, err := conf.introspector.Introspect(r.Context(), tokenString)
				if errors.Is(err, ErrInvalidAPIToken) {
					liberrors.NewApiError(liberrors.Unauthorized, errors.New("invalid or expired API token")).WriteHTTP(w)
					return
				}
				if err != nil {
					// Fail closed, but distinguishably: the token may well be
					// valid, the authentication service just could not say.
					liberrors.NewApiError(liberrors.ApiReason(http.StatusServiceUnavailable), errors.New("unable to verify API token")).WriteHTTP(w)
					return
				}
				auth = authContext{userID: userID, permissions: permissions, method: LoginMethodAPIToken}
			} else {
				verified, err := VerifyToken(publicKey, tokenString)
				if err != nil {
					liberrors.NewApiError(liberrors.Unauthorized, errors.New("invalid or expired token")).WriteHTTP(w)
					return
				}
				auth = authContext{userID: verified.UserID, permissions: verified.Permissions, method: verified.LoginMethod}
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), userIDContextKey{}, auth)))
		})
	}
}
