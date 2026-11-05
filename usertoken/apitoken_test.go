package usertoken

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestGenerateParseAPIToken(t *testing.T) {
	token, publicID, hash, err := GenerateAPIToken()
	if err != nil {
		t.Fatal(err)
	}
	if !IsAPIToken(token) {
		t.Fatalf("generated token %q lacks the prefix", token)
	}
	gotID, gotHash, ok := ParseAPIToken(token)
	if !ok || gotID != publicID || !bytes.Equal(gotHash, hash) {
		t.Fatalf("ParseAPIToken = (%q, %x, %v), want (%q, %x, true)", gotID, gotHash, ok, publicID, hash)
	}
	other, _, _, _ := GenerateAPIToken()
	if other == token {
		t.Fatal("two generated tokens are identical")
	}
}

func TestParseAPITokenRejectsMalformed(t *testing.T) {
	valid, _, _, err := GenerateAPIToken()
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]string{
		"empty":              "",
		"prefix only":        APITokenPrefix,
		"truncated":          valid[:len(valid)-1],
		"extended":           valid + "0",
		"uppercase prefix":   strings.ToUpper(valid[:len(APITokenPrefix)]) + valid[len(APITokenPrefix):],
		"wrong separator":    valid[:len(APITokenPrefix)+16] + "-" + valid[len(APITokenPrefix)+17:],
		"non-hex secret":     valid[:len(valid)-1] + "z",
		"use token":          "eyJhbGciOiJSUzI1NiJ9.e30.sig",
		"other prefix":       "humi_xxx_" + valid[len(APITokenPrefix):],
		"upper secret chars": valid[:len(valid)-4] + "ABCD",
	}
	for name, token := range tests {
		t.Run(name, func(t *testing.T) {
			if _, _, ok := ParseAPIToken(token); ok {
				t.Fatalf("ParseAPIToken accepted %q", token)
			}
		})
	}
}

func TestLoginMethodRoundTrip(t *testing.T) {
	key := newKey(t)
	for _, method := range []LoginMethod{LoginMethodLocal, LoginMethodCloud, LoginMethodImpersonation} {
		token, err := Sign(key, 1, time.Minute, Permissions{}, WithLoginMethod(method))
		if err != nil {
			t.Fatal(err)
		}
		verified, err := VerifyToken(&key.PublicKey, token)
		if err != nil || verified.LoginMethod != method {
			t.Fatalf("method %q round-tripped as (%q, %v)", method, verified.LoginMethod, err)
		}
	}

	t.Run("absent claim is unknown", func(t *testing.T) {
		token, _ := Sign(key, 1, time.Minute, Permissions{})
		verified, err := VerifyToken(&key.PublicKey, token)
		if err != nil || verified.LoginMethod != LoginMethodUnknown {
			t.Fatalf("got (%q, %v), want unknown", verified.LoginMethod, err)
		}
	})

	t.Run("a use token can never claim to be an API token", func(t *testing.T) {
		token, _ := Sign(key, 1, time.Minute, Permissions{}, WithLoginMethod(LoginMethodAPIToken))
		verified, _ := VerifyToken(&key.PublicKey, token)
		if verified.LoginMethod != LoginMethodUnknown {
			t.Fatalf("Sign wrote lm=%q", verified.LoginMethod)
		}
		forged := rawToken(t, jwt.SigningMethodRS256, key, jwt.MapClaims{ClaimID: 1, ClaimLoginMethod: "api-token", "exp": time.Now().Add(time.Minute).Unix()})
		verified, _ = VerifyToken(&key.PublicKey, forged)
		if verified.LoginMethod != LoginMethodUnknown {
			t.Fatalf("lm=api-token in a JWT was read as %q", verified.LoginMethod)
		}
	})
}

func TestIntersectAndCovers(t *testing.T) {
	user := NewPermissions(map[string]ResourceGrant{
		ResourceDevices:         {Modify: accessAll},
		ResourceAutomationRules: {View: accessAll},
	})
	scope := NewPermissions(map[string]ResourceGrant{
		ResourceDevices:         {View: accessAll},
		ResourceAutomationRules: {Modify: accessAll},
		ResourceAdapters:        {View: accessAll},
	})
	got := user.Intersect(scope)
	if got.Admin() {
		t.Fatal("intersection of non-admins is admin")
	}
	if !got.HasView(ResourceDevices) || got.HasModify(ResourceDevices) {
		t.Error("devices: want view only")
	}
	if !got.HasView(ResourceAutomationRules) || got.HasModify(ResourceAutomationRules) {
		t.Error("automation rules: want view only")
	}
	if got.HasView(ResourceAdapters) {
		t.Error("adapters: want no access, the user has none")
	}
	if !scope.Intersect(user).Covers(got) || !got.Covers(scope.Intersect(user)) {
		t.Error("Intersect is not symmetric")
	}

	if g := AdminPermissions().Intersect(scope); g.Admin() || !g.HasView(ResourceAdapters) || g.HasModify(ResourceDevices) {
		t.Error("admin ∩ scope should equal scope")
	}
	if !AdminPermissions().Intersect(AdminPermissions()).Admin() {
		t.Error("admin ∩ admin should be admin")
	}

	if user.Covers(scope) {
		t.Error("user covers a scope with adapters, which they lack")
	}
	if !user.Covers(NewPermissions(map[string]ResourceGrant{ResourceDevices: {Modify: accessAll}})) {
		t.Error("user should cover their own modify grant")
	}
	if user.Covers(AdminPermissions()) {
		t.Error("non-admin covers admin")
	}
	if !AdminPermissions().Covers(scope) {
		t.Error("admin should cover anything")
	}
}

type fakeIntrospector struct {
	userID      int64
	permissions Permissions
	err         error
	calls       int
}

func (f *fakeIntrospector) Introspect(context.Context, string) (int64, Permissions, error) {
	f.calls++
	return f.userID, f.permissions, f.err
}

func TestMiddlewareAPITokens(t *testing.T) {
	key := newKey(t)
	useToken, err := Sign(key, 42, time.Minute, AdminPermissions(), WithLoginMethod(LoginMethodLocal))
	if err != nil {
		t.Fatal(err)
	}
	apiToken, _, _, err := GenerateAPIToken()
	if err != nil {
		t.Fatal(err)
	}
	devicesView := NewPermissions(map[string]ResourceGrant{ResourceDevices: {View: accessAll}})

	tests := []struct {
		name         string
		opts         func(*fakeIntrospector) []MiddlewareOption
		introspector fakeIntrospector
		path         string
		token        string
		wantStatus   int
		wantMethod   LoginMethod
		wantCalls    int
	}{
		{
			name:       "refused by default",
			opts:       func(*fakeIntrospector) []MiddlewareOption { return nil },
			path:       "/x",
			token:      apiToken,
			wantStatus: http.StatusForbidden,
		},
		{
			name:         "accepted when opted in",
			opts:         func(f *fakeIntrospector) []MiddlewareOption { return []MiddlewareOption{AcceptAPITokens(f)} },
			introspector: fakeIntrospector{userID: 7, permissions: devicesView},
			path:         "/x",
			token:        apiToken,
			wantStatus:   http.StatusOK,
			wantMethod:   LoginMethodAPIToken,
			wantCalls:    1,
		},
		{
			name: "refused on an overridden route",
			opts: func(f *fakeIntrospector) []MiddlewareOption {
				return []MiddlewareOption{AcceptAPITokens(f), RejectAPITokensFor("/admin")}
			},
			introspector: fakeIntrospector{userID: 7},
			path:         "/admin/thing",
			token:        apiToken,
			wantStatus:   http.StatusForbidden,
		},
		{
			name: "use token still works on an overridden route",
			opts: func(f *fakeIntrospector) []MiddlewareOption {
				return []MiddlewareOption{AcceptAPITokens(f), RejectAPITokensFor("/admin")}
			},
			path:       "/admin/thing",
			token:      useToken,
			wantStatus: http.StatusOK,
			wantMethod: LoginMethodLocal,
		},
		{
			name:         "invalid API token",
			opts:         func(f *fakeIntrospector) []MiddlewareOption { return []MiddlewareOption{AcceptAPITokens(f)} },
			introspector: fakeIntrospector{err: ErrInvalidAPIToken},
			path:         "/x",
			token:        apiToken,
			wantStatus:   http.StatusUnauthorized,
			wantCalls:    1,
		},
		{
			name:         "authentication service unreachable",
			opts:         func(f *fakeIntrospector) []MiddlewareOption { return []MiddlewareOption{AcceptAPITokens(f)} },
			introspector: fakeIntrospector{err: errors.New("connection refused")},
			path:         "/x",
			token:        apiToken,
			wantStatus:   http.StatusServiceUnavailable,
			wantCalls:    1,
		},
		{
			name: "skipped prefix never introspects",
			opts: func(f *fakeIntrospector) []MiddlewareOption {
				return []MiddlewareOption{AcceptAPITokens(f), SkipPrefixes("/docs")}
			},
			introspector: fakeIntrospector{userID: 7},
			path:         "/docs/x",
			token:        apiToken,
			wantStatus:   http.StatusOK,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			introspector := tc.introspector
			var gotMethod LoginMethod
			h := NewMiddleware(&key.PublicKey, tc.opts(&introspector)...)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotMethod, _ = LoginMethodFromContext(r.Context())
				if gotMethod == LoginMethodAPIToken {
					if id, _ := UserID(r.Context()); id != 7 {
						t.Errorf("UserID = %d, want 7", id)
					}
					if p, _ := PermissionsFromContext(r.Context()); !p.HasView(ResourceDevices) || p.Admin() {
						t.Errorf("permissions not taken from introspection: %+v", p)
					}
					if !IsAPITokenRequest(r.Context()) {
						t.Error("IsAPITokenRequest = false for an API token")
					}
				}
			}))
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			req.Header.Set("Authorization", "Bearer "+tc.token)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (%s)", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if gotMethod != tc.wantMethod {
				t.Errorf("login method = %q, want %q", gotMethod, tc.wantMethod)
			}
			if introspector.calls != tc.wantCalls {
				t.Errorf("introspection calls = %d, want %d", introspector.calls, tc.wantCalls)
			}
		})
	}
}

// fakeAuthService serves IntrospectPath the way the authentication service
// does, answering with handler's result and counting calls.
func fakeAuthService(t *testing.T, handler func(w http.ResponseWriter, req IntrospectRequest)) (*httptest.Server, *atomic.Int32, string) {
	t.Helper()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != IntrospectPath || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer sa-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var req IntrospectRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode request: %v", err)
		}
		handler(w, req)
	}))
	t.Cleanup(srv.Close)
	saPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(saPath, []byte("sa-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return srv, &calls, saPath
}

func TestIntrospector(t *testing.T) {
	token, _, _, err := GenerateAPIToken()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("valid token is cached", func(t *testing.T) {
		srv, calls, saPath := fakeAuthService(t, func(w http.ResponseWriter, req IntrospectRequest) {
			if req.Token != token {
				t.Errorf("token = %q", req.Token)
			}
			w.Write([]byte(`{"userId": 9, "permissions": {"ds": {"v": "*"}}}`))
		})
		i := NewIntrospector(srv.URL+"/", saPath)
		for n := 0; n < 3; n++ {
			id, p, err := i.Introspect(context.Background(), token)
			if err != nil || id != 9 || !p.HasView(ResourceDevices) || p.HasModify(ResourceDevices) {
				t.Fatalf("Introspect = (%d, %+v, %v)", id, p, err)
			}
		}
		if calls.Load() != 1 {
			t.Fatalf("calls = %d, want 1 (cached)", calls.Load())
		}
	})

	t.Run("cache expires", func(t *testing.T) {
		srv, calls, saPath := fakeAuthService(t, func(w http.ResponseWriter, _ IntrospectRequest) {
			w.Write([]byte(`{"userId": 9, "permissions": {}}`))
		})
		now := time.Now()
		i := NewIntrospector(srv.URL, saPath, WithCacheTTL(30*time.Second, 10*time.Second))
		i.now = func() time.Time { return now }
		i.Introspect(context.Background(), token)
		now = now.Add(31 * time.Second)
		i.Introspect(context.Background(), token)
		if calls.Load() != 2 {
			t.Fatalf("calls = %d, want 2", calls.Load())
		}
	})

	t.Run("cache never outlives the token", func(t *testing.T) {
		now := time.Now()
		expires := now.Add(5 * time.Second)
		srv, calls, saPath := fakeAuthService(t, func(w http.ResponseWriter, _ IntrospectRequest) {
			json.NewEncoder(w).Encode(map[string]any{"userId": 9, "permissions": map[string]any{}, "expiresAt": expires})
		})
		i := NewIntrospector(srv.URL, saPath)
		i.now = func() time.Time { return now }
		i.Introspect(context.Background(), token)
		now = now.Add(6 * time.Second)
		i.Introspect(context.Background(), token)
		if calls.Load() != 2 {
			t.Fatalf("calls = %d, want 2: a result was served past the token's expiry", calls.Load())
		}
	})

	t.Run("invalid token is negatively cached", func(t *testing.T) {
		srv, calls, saPath := fakeAuthService(t, func(w http.ResponseWriter, _ IntrospectRequest) {
			w.Header().Set(IntrospectInvalidHeader, "1")
			w.WriteHeader(http.StatusUnauthorized)
		})
		i := NewIntrospector(srv.URL, saPath)
		for n := 0; n < 2; n++ {
			if _, _, err := i.Introspect(context.Background(), token); !errors.Is(err, ErrInvalidAPIToken) {
				t.Fatalf("err = %v, want ErrInvalidAPIToken", err)
			}
		}
		if calls.Load() != 1 {
			t.Fatalf("calls = %d, want 1", calls.Load())
		}
	})

	t.Run("own credentials refused is not an invalid token", func(t *testing.T) {
		srv, calls, _ := fakeAuthService(t, func(http.ResponseWriter, IntrospectRequest) {})
		wrongSA := filepath.Join(t.TempDir(), "token")
		os.WriteFile(wrongSA, []byte("someone-else"), 0o600)
		i := NewIntrospector(srv.URL, wrongSA)
		for n := 0; n < 2; n++ {
			_, _, err := i.Introspect(context.Background(), token)
			if err == nil || errors.Is(err, ErrInvalidAPIToken) {
				t.Fatalf("err = %v, want a non-ErrInvalidAPIToken error", err)
			}
		}
		if calls.Load() != 2 {
			t.Fatalf("calls = %d, want 2 (errors are not cached)", calls.Load())
		}
	})

	t.Run("malformed token never calls out", func(t *testing.T) {
		srv, calls, saPath := fakeAuthService(t, func(http.ResponseWriter, IntrospectRequest) {})
		i := NewIntrospector(srv.URL, saPath)
		if _, _, err := i.Introspect(context.Background(), APITokenPrefix+"nope"); !errors.Is(err, ErrInvalidAPIToken) {
			t.Fatalf("err = %v", err)
		}
		if calls.Load() != 0 {
			t.Fatalf("calls = %d, want 0", calls.Load())
		}
	})
}
