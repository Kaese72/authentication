package usertoken

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// IntrospectPath is the authentication service's internal-listener endpoint
// that looks up an API token. Its request and response bodies are
// IntrospectRequest and IntrospectResponse.
const IntrospectPath = "/authentication-service/v0/internal/api-tokens/introspect"

// IntrospectRequest is the body of a POST to IntrospectPath.
type IntrospectRequest struct {
	Token string `json:"token"`
}

// IntrospectResponse is the body of a successful (200) response from
// IntrospectPath. Permissions are already narrowed to what the token's owner
// currently has, so a demoted or deleted user's tokens shrink or stop working
// without the tokens themselves being touched. An unknown, expired or
// malformed token is answered with 401 instead.
type IntrospectResponse struct {
	UserID      int64       `json:"userId"`
	Permissions Permissions `json:"permissions"`
	// ExpiresAt is when the token itself expires, nil if never. A cache must
	// not keep the result past it.
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`
}

// ErrInvalidAPIToken means the authentication service does not recognize an
// API token (unknown, revoked, expired or malformed): the caller gets 401.
// Any other Introspect error means it could not be asked.
var ErrInvalidAPIToken = errors.New("invalid API token")

// APITokenIntrospector looks an API token up. *Introspector is the real
// implementation; tests can supply their own.
type APITokenIntrospector interface {
	Introspect(ctx context.Context, token string) (userID int64, permissions Permissions, err error)
}

// Introspector looks API tokens up in the authentication service, as the
// calling service's own Kubernetes ServiceAccount, and caches the answers
// briefly. The cache TTL is the upper bound on how long a revoked token, or a
// permission taken away from its owner, keeps working in this service.
type Introspector struct {
	baseURL                 string
	serviceAccountTokenPath string
	httpClient              *http.Client
	positiveTTL             time.Duration
	negativeTTL             time.Duration
	maxEntries              int
	now                     func() time.Time

	mu    sync.Mutex
	cache map[[sha256.Size]byte]introspectCacheEntry
}

type introspectCacheEntry struct {
	userID      int64
	permissions Permissions
	invalid     bool
	expires     time.Time
}

// IntrospectorOption configures NewIntrospector.
type IntrospectorOption func(*Introspector)

// WithCacheTTL sets how long a valid (positive) and an invalid (negative)
// answer is cached. Defaults: 30s and 10s. Zero disables caching for that
// kind of answer.
func WithCacheTTL(positive, negative time.Duration) IntrospectorOption {
	return func(i *Introspector) { i.positiveTTL, i.negativeTTL = positive, negative }
}

// WithHTTPClient replaces the default HTTP client (5s timeout).
func WithHTTPClient(client *http.Client) IntrospectorOption {
	return func(i *Introspector) { i.httpClient = client }
}

// NewIntrospector returns an Introspector calling the authentication
// service's internal listener at baseURL (e.g.
// "http://authentication:8081"), presenting the projected, audience-bound
// ServiceAccount token at serviceAccountTokenPath. The file is re-read on
// every call, since kubelet rotates it. The calling service's ServiceAccount
// must be allow-listed for introspection by the authentication service.
func NewIntrospector(baseURL string, serviceAccountTokenPath string, opts ...IntrospectorOption) *Introspector {
	i := &Introspector{
		baseURL:                 strings.TrimRight(baseURL, "/"),
		serviceAccountTokenPath: serviceAccountTokenPath,
		httpClient:              &http.Client{Timeout: 5 * time.Second},
		positiveTTL:             30 * time.Second,
		negativeTTL:             10 * time.Second,
		maxEntries:              1024,
		now:                     time.Now,
		cache:                   map[[sha256.Size]byte]introspectCacheEntry{},
	}
	for _, opt := range opts {
		opt(i)
	}
	return i
}

// Introspect returns the user an API token belongs to and the permissions it
// grants, or ErrInvalidAPIToken. Tokens not in the API token format are
// rejected without a call.
func (i *Introspector) Introspect(ctx context.Context, token string) (int64, Permissions, error) {
	if _, _, ok := ParseAPIToken(token); !ok {
		return 0, Permissions{}, ErrInvalidAPIToken
	}
	key := sha256.Sum256([]byte(token))
	if entry, ok := i.cached(key); ok {
		if entry.invalid {
			return 0, Permissions{}, ErrInvalidAPIToken
		}
		return entry.userID, entry.permissions, nil
	}

	resp, err := i.call(ctx, token)
	if errors.Is(err, ErrInvalidAPIToken) {
		i.store(key, introspectCacheEntry{invalid: true}, i.negativeTTL, nil)
		return 0, Permissions{}, err
	}
	if err != nil {
		// Not cached: the next request should try again.
		return 0, Permissions{}, err
	}
	i.store(key, introspectCacheEntry{userID: resp.UserID, permissions: resp.Permissions}, i.positiveTTL, resp.ExpiresAt)
	return resp.UserID, resp.Permissions, nil
}

func (i *Introspector) call(ctx context.Context, token string) (IntrospectResponse, error) {
	serviceToken, err := os.ReadFile(i.serviceAccountTokenPath)
	if err != nil {
		return IntrospectResponse{}, fmt.Errorf("read service account token: %w", err)
	}
	body, err := json.Marshal(IntrospectRequest{Token: token})
	if err != nil {
		return IntrospectResponse{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, i.baseURL+IntrospectPath, bytes.NewReader(body))
	if err != nil {
		return IntrospectResponse{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(serviceToken)))
	httpResp, err := i.httpClient.Do(req)
	if err != nil {
		return IntrospectResponse{}, err
	}
	defer httpResp.Body.Close()
	switch httpResp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized:
		// The internal listener also answers 401 when it rejects this
		// service's own ServiceAccount token - but then with no JSON body
		// from the introspection handler. Only trust a 401 as "token
		// invalid" when the handler produced it.
		if httpResp.Header.Get(IntrospectInvalidHeader) == "1" {
			return IntrospectResponse{}, ErrInvalidAPIToken
		}
		respBody, _ := io.ReadAll(io.LimitReader(httpResp.Body, 1024))
		return IntrospectResponse{}, fmt.Errorf("authentication service refused introspection call: %s", respBody)
	default:
		respBody, _ := io.ReadAll(io.LimitReader(httpResp.Body, 1024))
		return IntrospectResponse{}, fmt.Errorf("authentication service returned %d for introspection: %s", httpResp.StatusCode, respBody)
	}
	var out IntrospectResponse
	if err := json.NewDecoder(httpResp.Body).Decode(&out); err != nil {
		return IntrospectResponse{}, fmt.Errorf("decode introspection response: %w", err)
	}
	if out.UserID < 1 {
		return IntrospectResponse{}, errors.New("introspection response has no user id")
	}
	return out, nil
}

// IntrospectInvalidHeader is set to "1" on the introspection endpoint's 401
// response, so Introspector can tell "this API token is invalid" (cache it,
// answer 401) apart from "this service's own credentials were refused" (a
// misconfiguration, answer 503 and do not cache).
const IntrospectInvalidHeader = "X-Humi-Api-Token-Invalid"

func (i *Introspector) cached(key [sha256.Size]byte) (introspectCacheEntry, bool) {
	i.mu.Lock()
	defer i.mu.Unlock()
	entry, ok := i.cache[key]
	if !ok {
		return introspectCacheEntry{}, false
	}
	if !i.now().Before(entry.expires) {
		delete(i.cache, key)
		return introspectCacheEntry{}, false
	}
	return entry, true
}

func (i *Introspector) store(key [sha256.Size]byte, entry introspectCacheEntry, ttl time.Duration, tokenExpiresAt *time.Time) {
	if ttl <= 0 {
		return
	}
	now := i.now()
	entry.expires = now.Add(ttl)
	if tokenExpiresAt != nil && tokenExpiresAt.Before(entry.expires) {
		entry.expires = *tokenExpiresAt
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if len(i.cache) >= i.maxEntries {
		for k, e := range i.cache {
			if !now.Before(e.expires) {
				delete(i.cache, k)
			}
		}
		if len(i.cache) >= i.maxEntries {
			// Still full of live entries: start over rather than track
			// recency. Costs a burst of re-introspection, nothing more.
			i.cache = map[[sha256.Size]byte]introspectCacheEntry{}
		}
	}
	i.cache[key] = entry
}
