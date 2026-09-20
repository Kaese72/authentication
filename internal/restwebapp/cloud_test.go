package restwebapp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"database/sql"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/Kaese72/authentication/internal/cloudclient"
	"github.com/Kaese72/authentication/internal/persistence"
	"github.com/Kaese72/authentication/restmodels"
	"github.com/danielgtaylor/huma/v2"
	"github.com/go-sql-driver/mysql"
)

type fakeStore struct {
	users  map[int64]persistence.User
	states map[string]bool
	nextID int64
	// usernames already taken by other (local) users
	takenUsernames map[string]bool
}

func newFakeStore() *fakeStore {
	return &fakeStore{users: map[int64]persistence.User{}, states: map[string]bool{}, nextID: 1, takenUsernames: map[string]bool{}}
}

func (s *fakeStore) GetUserByUsername(_ context.Context, username string) (persistence.User, error) {
	for _, u := range s.users {
		if u.Username == username {
			return u, nil
		}
	}
	return persistence.User{}, sql.ErrNoRows
}

func (s *fakeStore) GetUserByID(_ context.Context, id int64) (persistence.User, error) {
	if u, ok := s.users[id]; ok {
		return u, nil
	}
	return persistence.User{}, sql.ErrNoRows
}

func (s *fakeStore) GetUserByCloudUserID(_ context.Context, cloudUserID int64) (persistence.User, error) {
	for _, u := range s.users {
		if u.CloudUserID != nil && *u.CloudUserID == cloudUserID {
			return u, nil
		}
	}
	return persistence.User{}, sql.ErrNoRows
}

func (s *fakeStore) CreateCloudUser(_ context.Context, cloudUserID int64, username string, name string, surname string, email *string) error {
	if s.takenUsernames[username] {
		return &mysql.MySQLError{Number: 1062}
	}
	s.takenUsernames[username] = true
	id := s.nextID
	s.nextID++
	s.users[id] = persistence.User{ID: id, Username: username, Name: name, Surname: surname, Email: email, CloudUserID: &cloudUserID}
	return nil
}

func (s *fakeStore) UpdateUser(_ context.Context, id int64, name string, surname string, email *string) error {
	u := s.users[id]
	u.Name, u.Surname, u.Email = name, surname, email
	s.users[id] = u
	return nil
}

func (s *fakeStore) SaveCloudLoginState(_ context.Context, state string, _ time.Time) error {
	s.states[state] = true
	return nil
}

func (s *fakeStore) ConsumeCloudLoginState(_ context.Context, state string) (bool, error) {
	ok := s.states[state]
	delete(s.states, state)
	return ok, nil
}

type fakeCloud struct {
	allowed     bool
	accessErr   error
	redeemUser  cloudclient.CloudUser
	redeemErr   error
	accessCalls int
}

func (c *fakeCloud) Available(context.Context) (bool, error) { return true, nil }
func (c *fakeCloud) Start(_ context.Context, state string, _ string) (string, error) {
	return "https://cloud.example/appliance-login?state=" + state, nil
}
func (c *fakeCloud) Redeem(context.Context, string) (cloudclient.CloudUser, error) {
	return c.redeemUser, c.redeemErr
}
func (c *fakeCloud) CheckAccess(context.Context, int64) (bool, error) {
	c.accessCalls++
	return c.allowed, c.accessErr
}

func newTestApp(t *testing.T, store *fakeStore, cloud *fakeCloud) webApp {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return NewWebApp(store, key, "refresh-secret", 10*time.Minute, 7*24*time.Hour, cloud, 5*time.Minute, 24*time.Hour)
}

type loginInput = struct {
	CookieHeader string `header:"Cookie"`
	Body         *restmodels.LoginRequest
}

func refreshInput(t *testing.T, app webApp, userID int64, cloudVerifiedAt time.Time) *loginInput {
	t.Helper()
	token, err := generateRefreshToken(app.refreshSecret, userID, time.Hour, cloudVerifiedAt)
	if err != nil {
		t.Fatal(err)
	}
	return &loginInput{CookieHeader: (&http.Cookie{Name: refreshCookieName, Value: token}).String()}
}

func statusOf(err error) int {
	var se huma.StatusError
	if errors.As(err, &se) {
		return se.GetStatus()
	}
	return 0
}

func addCloudUser(store *fakeStore, cloudID int64) int64 {
	id := store.nextID
	store.nextID++
	store.users[id] = persistence.User{ID: id, Username: "cloud-user", Name: "C", Surname: "U", CloudUserID: &cloudID}
	return id
}

func TestRefreshCloudUserStillAllowed(t *testing.T) {
	store, cloud := newFakeStore(), &fakeCloud{allowed: true}
	app := newTestApp(t, store, cloud)
	id := addCloudUser(store, 42)

	res, err := app.Login(context.Background(), refreshInput(t, app, id, time.Now().Add(-time.Hour)))
	if err != nil {
		t.Fatalf("expected refresh to succeed, got %v", err)
	}
	if res.Body.UseToken == "" {
		t.Error("expected a use token")
	}
	if cloud.accessCalls != 1 {
		t.Errorf("expected exactly one cloud access check, got %d", cloud.accessCalls)
	}
}

func TestRefreshCloudUserRevoked(t *testing.T) {
	store, cloud := newFakeStore(), &fakeCloud{allowed: false}
	app := newTestApp(t, store, cloud)
	id := addCloudUser(store, 42)

	_, err := app.Login(context.Background(), refreshInput(t, app, id, time.Now()))
	if statusOf(err) != http.StatusUnauthorized {
		t.Fatalf("expected 401 for revoked access, got %v", err)
	}
}

func TestRefreshCloudUnreachableWithinGrace(t *testing.T) {
	store, cloud := newFakeStore(), &fakeCloud{accessErr: errors.New("connection refused")}
	app := newTestApp(t, store, cloud)
	id := addCloudUser(store, 42)

	if _, err := app.Login(context.Background(), refreshInput(t, app, id, time.Now().Add(-time.Hour))); err != nil {
		t.Fatalf("expected refresh to succeed within the grace period, got %v", err)
	}
}

func TestRefreshCloudUnreachableGraceExpired(t *testing.T) {
	store, cloud := newFakeStore(), &fakeCloud{accessErr: errors.New("connection refused")}
	app := newTestApp(t, store, cloud)
	id := addCloudUser(store, 42)

	_, err := app.Login(context.Background(), refreshInput(t, app, id, time.Now().Add(-25*time.Hour)))
	if statusOf(err) != http.StatusUnauthorized {
		t.Fatalf("expected 401 once the grace period has passed, got %v", err)
	}
}

func TestRefreshGraceDoesNotSlide(t *testing.T) {
	// Refreshing while the cloud is unreachable must not reset the clock,
	// or an outage (or a blocked cloud) would extend access indefinitely.
	store, cloud := newFakeStore(), &fakeCloud{accessErr: errors.New("connection refused")}
	app := newTestApp(t, store, cloud)
	id := addCloudUser(store, 42)
	verified := time.Now().Add(-time.Hour).Truncate(time.Second)

	res, err := app.Login(context.Background(), refreshInput(t, app, id, verified))
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := (&http.Request{Header: http.Header{"Cookie": []string{res.SetCookie}}}).Cookie(refreshCookieName)
	if err != nil {
		t.Fatal(err)
	}
	_, got, err := validateRefreshToken(app.refreshSecret, cookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(verified) {
		t.Errorf("cloudVerifiedAt moved from %v to %v while the cloud was unreachable", verified, got)
	}
}

func TestRefreshCloudNoLongerEnrolledDeniesImmediately(t *testing.T) {
	store, cloud := newFakeStore(), &fakeCloud{accessErr: cloudclient.ErrNotEnrolled}
	app := newTestApp(t, store, cloud)
	id := addCloudUser(store, 42)

	_, err := app.Login(context.Background(), refreshInput(t, app, id, time.Now()))
	if statusOf(err) != http.StatusUnauthorized {
		t.Fatalf("expected 401 when the appliance is no longer enrolled, got %v", err)
	}
}

func TestRefreshLocalUserNeverAsksCloud(t *testing.T) {
	store, cloud := newFakeStore(), &fakeCloud{}
	app := newTestApp(t, store, cloud)
	store.users[1] = persistence.User{ID: 1, Username: "local", PasswordHash: "x"}

	if _, err := app.Login(context.Background(), refreshInput(t, app, 1, time.Time{})); err != nil {
		t.Fatal(err)
	}
	if cloud.accessCalls != 0 {
		t.Errorf("local users must not trigger a cloud check, got %d", cloud.accessCalls)
	}
}

func TestRefreshDeletedUserIsRejected(t *testing.T) {
	store, cloud := newFakeStore(), &fakeCloud{}
	app := newTestApp(t, store, cloud)

	_, err := app.Login(context.Background(), refreshInput(t, app, 99, time.Time{}))
	if statusOf(err) != http.StatusUnauthorized {
		t.Fatalf("expected 401 for a refresh token of a deleted user, got %v", err)
	}
}

func TestCloudUserCannotLogInWithPassword(t *testing.T) {
	store, cloud := newFakeStore(), &fakeCloud{}
	app := newTestApp(t, store, cloud)
	addCloudUser(store, 42)
	username, password := "cloud-user", "anything"

	_, err := app.Login(context.Background(), &loginInput{Body: &restmodels.LoginRequest{Username: &username, Password: &password}})
	if statusOf(err) != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %v", err)
	}
}

func TestCloudCompleteCreatesUserOnceAndRejectsReusedState(t *testing.T) {
	store := newFakeStore()
	cloud := &fakeCloud{redeemUser: cloudclient.CloudUser{ID: 7, Username: "alice", Name: "Alice", Surname: "A", Email: "a@example.com"}}
	app := newTestApp(t, store, cloud)
	store.states["s1"], store.states["s2"] = true, true

	first, err := app.CloudComplete(context.Background(), &struct {
		Body restmodels.CloudLoginCompleteRequest
	}{Body: restmodels.CloudLoginCompleteRequest{Code: "c", State: "s1"}})
	if err != nil {
		t.Fatal(err)
	}
	if first.Body.UseToken == "" || len(store.users) != 1 {
		t.Fatalf("expected one user and a token, got %d users", len(store.users))
	}

	if _, err := app.CloudComplete(context.Background(), &struct {
		Body restmodels.CloudLoginCompleteRequest
	}{Body: restmodels.CloudLoginCompleteRequest{Code: "c", State: "s2"}}); err != nil {
		t.Fatal(err)
	}
	if len(store.users) != 1 {
		t.Errorf("second login must reuse the existing user, got %d users", len(store.users))
	}

	_, err = app.CloudComplete(context.Background(), &struct {
		Body restmodels.CloudLoginCompleteRequest
	}{Body: restmodels.CloudLoginCompleteRequest{Code: "c", State: "s1"}})
	if statusOf(err) != http.StatusUnauthorized {
		t.Fatalf("expected 401 for a reused state, got %v", err)
	}
}

func TestCloudCompleteUsernameCollisionDoesNotTakeOverLocalUser(t *testing.T) {
	store := newFakeStore()
	store.takenUsernames["alice"] = true
	store.users[1] = persistence.User{ID: 1, Username: "alice", PasswordHash: "x"}
	store.nextID = 2
	cloud := &fakeCloud{redeemUser: cloudclient.CloudUser{ID: 7, Username: "alice", Name: "Alice", Surname: "A"}}
	app := newTestApp(t, store, cloud)
	store.states["s"] = true

	res, err := app.CloudComplete(context.Background(), &struct {
		Body restmodels.CloudLoginCompleteRequest
	}{Body: restmodels.CloudLoginCompleteRequest{Code: "c", State: "s"}})
	if err != nil || res.Body.UseToken == "" {
		t.Fatalf("expected login to succeed, got %v", err)
	}
	if store.users[1].CloudUserID != nil {
		t.Error("the pre-existing local user must not be linked to the cloud user")
	}
	if len(store.users) != 2 {
		t.Errorf("expected a second, distinct user, got %d users", len(store.users))
	}
}

func TestCloudCompleteRefusedByCloud(t *testing.T) {
	store := newFakeStore()
	cloud := &fakeCloud{redeemErr: cloudclient.ErrRefused}
	app := newTestApp(t, store, cloud)
	store.states["s"] = true

	_, err := app.CloudComplete(context.Background(), &struct {
		Body restmodels.CloudLoginCompleteRequest
	}{Body: restmodels.CloudLoginCompleteRequest{Code: "c", State: "s"}})
	if statusOf(err) != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %v", err)
	}
	if len(store.users) != 0 {
		t.Error("no user may be created when the cloud refuses the login")
	}
}
