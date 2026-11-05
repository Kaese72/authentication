package apitokenwebapp

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/Kaese72/authentication/internal/persistence"
	"github.com/Kaese72/authentication/restmodels"
	"github.com/Kaese72/authentication/usertoken"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/humatest"
)

type fakeStore struct {
	users   map[int64]persistence.User
	tokens  map[int64]persistence.APIToken
	nextID  int64
	touches int
}

func newFakeStore() *fakeStore {
	return &fakeStore{users: map[int64]persistence.User{}, tokens: map[int64]persistence.APIToken{}, nextID: 1}
}

func (s *fakeStore) GetUserByID(_ context.Context, id int64) (persistence.User, error) {
	if u, ok := s.users[id]; ok {
		return u, nil
	}
	return persistence.User{}, sql.ErrNoRows
}

func (s *fakeStore) CreateAPIToken(_ context.Context, token persistence.APIToken) (int64, error) {
	token.ID = s.nextID
	s.nextID++
	s.tokens[token.ID] = token
	return token.ID, nil
}

func (s *fakeStore) ListAPITokens(_ context.Context, userID int64) ([]persistence.APIToken, error) {
	out := []persistence.APIToken{}
	for _, t := range s.tokens {
		if t.UserID == userID {
			out = append(out, t)
		}
	}
	return out, nil
}

func (s *fakeStore) DeleteAPIToken(_ context.Context, userID int64, id int64) error {
	t, ok := s.tokens[id]
	if !ok || t.UserID != userID {
		return sql.ErrNoRows
	}
	delete(s.tokens, id)
	return nil
}

func (s *fakeStore) GetAPITokenByPublicID(_ context.Context, publicID string) (persistence.APIToken, error) {
	for _, t := range s.tokens {
		if t.PublicID == publicID {
			return t, nil
		}
	}
	return persistence.APIToken{}, sql.ErrNoRows
}

func (s *fakeStore) TouchAPIToken(_ context.Context, id int64, at time.Time) error {
	s.touches++
	t := s.tokens[id]
	t.LastUsedAt = &at
	s.tokens[id] = t
	return nil
}

func statusOf(err error) int {
	var se huma.StatusError
	if errors.As(err, &se) {
		return se.GetStatus()
	}
	return 0
}

var devicesModify = usertoken.NewPermissions(map[string]usertoken.ResourceGrant{
	usertoken.ResourceDevices: {Modify: "*"},
})

// addUser adds a user with a local password and the given permissions.
func addUser(s *fakeStore, permissions usertoken.Permissions) int64 {
	id := s.nextID
	s.nextID++
	s.users[id] = persistence.User{ID: id, Username: "u", PasswordHash: "hash", Permissions: permissions}
	return id
}

func loginCtx(userID int64, method usertoken.LoginMethod) context.Context {
	return usertoken.ContextWithLogin(context.Background(), userID, usertoken.Permissions{}, method)
}

func createInput(resources map[string]restmodels.ResourcePermission) *struct {
	Body restmodels.CreateAPITokenRequest
} {
	return &struct {
		Body restmodels.CreateAPITokenRequest
	}{Body: restmodels.CreateAPITokenRequest{Name: "ha", Resources: resources}}
}

var viewDevices = map[string]restmodels.ResourcePermission{usertoken.ResourceDevices: {View: true}}

func introspect(app webApp, token string) (*struct {
	Body restmodels.IntrospectAPITokenResponse
}, error) {
	return app.Introspect(context.Background(), &struct {
		Body restmodels.IntrospectAPITokenRequest
	}{Body: restmodels.IntrospectAPITokenRequest{Token: token}})
}

func TestCreateRequiresLocalLogin(t *testing.T) {
	for _, method := range []usertoken.LoginMethod{
		usertoken.LoginMethodCloud,
		usertoken.LoginMethodUnknown,
		usertoken.LoginMethodImpersonation,
		usertoken.LoginMethodAPIToken,
	} {
		t.Run(string(method), func(t *testing.T) {
			store := newFakeStore()
			app := NewWebApp(store)
			id := addUser(store, devicesModify)
			_, err := app.CreateMyAPIToken(loginCtx(id, method), createInput(viewDevices))
			if statusOf(err) != http.StatusForbidden {
				t.Fatalf("got %v, want 403", err)
			}
			if len(store.tokens) != 0 {
				t.Fatal("a token was stored anyway")
			}
		})
	}
}

func TestCreateRejectsUserWithoutPassword(t *testing.T) {
	store := newFakeStore()
	app := NewWebApp(store)
	id := addUser(store, devicesModify)
	u := store.users[id]
	u.PasswordHash = ""
	store.users[id] = u
	if _, err := app.CreateMyAPIToken(loginCtx(id, usertoken.LoginMethodLocal), createInput(viewDevices)); statusOf(err) != http.StatusForbidden {
		t.Fatalf("got %v, want 403", err)
	}
}

func TestCreateCannotExceedOwnPermissions(t *testing.T) {
	store := newFakeStore()
	app := NewWebApp(store)
	id := addUser(store, usertoken.NewPermissions(map[string]usertoken.ResourceGrant{usertoken.ResourceDevices: {View: "*"}}))
	_, err := app.CreateMyAPIToken(loginCtx(id, usertoken.LoginMethodLocal), createInput(map[string]restmodels.ResourcePermission{
		usertoken.ResourceDevices: {Modify: true},
	}))
	if statusOf(err) != http.StatusForbidden {
		t.Fatalf("got %v, want 403", err)
	}
}

func TestCreateValidation(t *testing.T) {
	store := newFakeStore()
	app := NewWebApp(store)
	id := addUser(store, usertoken.AdminPermissions())
	ctx := loginCtx(id, usertoken.LoginMethodLocal)

	if _, err := app.CreateMyAPIToken(ctx, createInput(map[string]restmodels.ResourcePermission{"zz": {View: true}})); statusOf(err) != http.StatusBadRequest {
		t.Errorf("unknown resource: got %v, want 400", err)
	}
	if _, err := app.CreateMyAPIToken(ctx, createInput(nil)); statusOf(err) != http.StatusBadRequest {
		t.Errorf("empty scope: got %v, want 400", err)
	}
	blank := createInput(viewDevices)
	blank.Body.Name = "   "
	if _, err := app.CreateMyAPIToken(ctx, blank); statusOf(err) != http.StatusBadRequest {
		t.Errorf("blank name: got %v, want 400", err)
	}
}

func TestCreateListDeleteIntrospect(t *testing.T) {
	store := newFakeStore()
	app := NewWebApp(store)
	// Even an admin's token carries only what it was scoped to.
	id := addUser(store, usertoken.AdminPermissions())

	created, err := app.CreateMyAPIToken(loginCtx(id, usertoken.LoginMethodLocal), createInput(viewDevices))
	if err != nil {
		t.Fatal(err)
	}
	if !usertoken.IsAPIToken(created.Body.Token) {
		t.Fatalf("returned token %q is not an API token", created.Body.Token)
	}
	if created.Body.APIToken.ExpiresAt != nil {
		t.Error("token without expiresInDays has an expiry")
	}
	for _, stored := range store.tokens {
		if stored.Permissions.Admin() {
			t.Fatal("stored token carries admin")
		}
	}

	res, err := introspect(app, created.Body.Token)
	if err != nil {
		t.Fatal(err)
	}
	if res.Body.UserID != id {
		t.Errorf("userId = %d, want %d", res.Body.UserID, id)
	}
	if _, admin := res.Body.Permissions["admin"]; admin {
		t.Error("introspection returned admin for a scoped token")
	}
	if _, ok := res.Body.Permissions[usertoken.ResourceDevices]; !ok {
		t.Errorf("introspection lost the devices grant: %v", res.Body.Permissions)
	}

	// Listing and deleting work from a cloud session.
	cloudCtx := loginCtx(id, usertoken.LoginMethodCloud)
	list, err := app.ListMyAPITokens(cloudCtx, &struct{}{})
	if err != nil || len(list.Body) != 1 {
		t.Fatalf("list = (%v, %v), want one token", list, err)
	}
	if list.Body[0].Prefix == "" || list.Body[0].Prefix == created.Body.Token {
		t.Errorf("prefix %q is empty or the whole token", list.Body[0].Prefix)
	}
	if _, err := app.DeleteMyAPIToken(cloudCtx, &struct {
		TokenID int64 `path:"tokenId"`
	}{TokenID: list.Body[0].ID}); err != nil {
		t.Fatalf("delete from a cloud session: %v", err)
	}
	if _, err := introspect(app, created.Body.Token); statusOf(err) != http.StatusUnauthorized {
		t.Fatalf("deleted token introspected as %v, want 401", err)
	}
}

func TestDeleteOtherUsersTokenIsNotFound(t *testing.T) {
	store := newFakeStore()
	app := NewWebApp(store)
	owner, other := addUser(store, devicesModify), addUser(store, devicesModify)
	created, err := app.CreateMyAPIToken(loginCtx(owner, usertoken.LoginMethodLocal), createInput(viewDevices))
	if err != nil {
		t.Fatal(err)
	}
	_, err = app.DeleteMyAPIToken(loginCtx(other, usertoken.LoginMethodLocal), &struct {
		TokenID int64 `path:"tokenId"`
	}{TokenID: created.Body.APIToken.ID})
	if statusOf(err) != http.StatusNotFound {
		t.Fatalf("got %v, want 404", err)
	}
	if len(store.tokens) != 1 {
		t.Fatal("another user's token was deleted")
	}
}

func TestIntrospectRejects(t *testing.T) {
	store := newFakeStore()
	app := NewWebApp(store)
	now := time.Now()
	app.now = func() time.Time { return now }
	id := addUser(store, devicesModify)
	days := 1
	in := createInput(viewDevices)
	in.Body.ExpiresInDays = &days
	created, err := app.CreateMyAPIToken(loginCtx(id, usertoken.LoginMethodLocal), in)
	if err != nil {
		t.Fatal(err)
	}
	token := created.Body.Token

	wrongSecret := token[:len(token)-1] + map[bool]string{true: "0", false: "1"}[token[len(token)-1] != '0']
	for name, tok := range map[string]string{
		"malformed":    "humi_pat_nope",
		"wrong secret": wrongSecret,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := introspect(app, tok)
			if statusOf(err) != http.StatusUnauthorized {
				t.Fatalf("got %v, want 401", err)
			}
			var hs huma.HeadersError
			if !errors.As(err, &hs) || hs.GetHeaders().Get(usertoken.IntrospectInvalidHeader) != "1" {
				t.Fatal("401 lacks the invalid-token header")
			}
		})
	}

	t.Run("expired", func(t *testing.T) {
		now = now.Add(25 * time.Hour)
		defer func() { now = now.Add(-25 * time.Hour) }()
		if _, err := introspect(app, token); statusOf(err) != http.StatusUnauthorized {
			t.Fatalf("got %v, want 401", err)
		}
	})

	t.Run("owner deleted", func(t *testing.T) {
		u := store.users[id]
		delete(store.users, id)
		defer func() { store.users[id] = u }()
		if _, err := introspect(app, token); statusOf(err) != http.StatusUnauthorized {
			t.Fatalf("got %v, want 401", err)
		}
	})
}

func TestIntrospectFollowsOwnersCurrentPermissions(t *testing.T) {
	store := newFakeStore()
	app := NewWebApp(store)
	id := addUser(store, devicesModify)
	created, err := app.CreateMyAPIToken(loginCtx(id, usertoken.LoginMethodLocal), createInput(map[string]restmodels.ResourcePermission{
		usertoken.ResourceDevices: {Modify: true},
	}))
	if err != nil {
		t.Fatal(err)
	}

	// The owner is demoted to view-only after creating the token.
	u := store.users[id]
	u.Permissions = usertoken.NewPermissions(map[string]usertoken.ResourceGrant{usertoken.ResourceDevices: {View: "*"}})
	store.users[id] = u

	res, err := introspect(app, created.Body.Token)
	if err != nil {
		t.Fatal(err)
	}
	grant, _ := res.Body.Permissions[usertoken.ResourceDevices].(map[string]any)
	if grant["v"] != "*" || grant["m"] != nil {
		t.Fatalf("devices grant = %v, want view only", grant)
	}
}

func TestIntrospectThrottlesLastUsed(t *testing.T) {
	store := newFakeStore()
	app := NewWebApp(store)
	now := time.Now()
	app.now = func() time.Time { return now }
	id := addUser(store, devicesModify)
	created, err := app.CreateMyAPIToken(loginCtx(id, usertoken.LoginMethodLocal), createInput(viewDevices))
	if err != nil {
		t.Fatal(err)
	}
	for n := 0; n < 3; n++ {
		if _, err := introspect(app, created.Body.Token); err != nil {
			t.Fatal(err)
		}
	}
	if store.touches != 1 {
		t.Fatalf("touches = %d, want 1", store.touches)
	}
	now = now.Add(2 * time.Minute)
	introspect(app, created.Body.Token)
	if store.touches != 2 {
		t.Fatalf("touches = %d, want 2", store.touches)
	}
}

// TestIntrospectInvalidHeaderOverHTTP checks the invalid-token marker really
// reaches the wire, since usertoken.Introspector relies on it to tell an
// invalid token apart from its own credentials being refused.
func TestIntrospectInvalidHeaderOverHTTP(t *testing.T) {
	_, api := humatest.New(t)
	app := NewWebApp(newFakeStore())
	huma.Post(api, usertoken.IntrospectPath, app.Introspect)
	resp := api.Post(usertoken.IntrospectPath, map[string]any{"token": "humi_pat_nope"})
	if resp.Code != http.StatusUnauthorized || resp.Header().Get(usertoken.IntrospectInvalidHeader) != "1" {
		t.Fatalf("status %d, header %q", resp.Code, resp.Header().Get(usertoken.IntrospectInvalidHeader))
	}
}
