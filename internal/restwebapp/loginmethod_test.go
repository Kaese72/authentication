package restwebapp

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/Kaese72/authentication/internal/persistence"
	"github.com/Kaese72/authentication/restmodels"
	"github.com/Kaese72/authentication/usertoken"
	"golang.org/x/crypto/bcrypt"
)

func loginMethodOf(t *testing.T, app webApp, res *loginResult) usertoken.LoginMethod {
	t.Helper()
	verified, err := usertoken.VerifyToken(&app.privateKey.PublicKey, res.Body.UseToken)
	if err != nil {
		t.Fatal(err)
	}
	return verified.LoginMethod
}

func refreshFrom(t *testing.T, res *loginResult) *loginInput {
	t.Helper()
	cookie, err := (&http.Request{Header: http.Header{"Cookie": []string{res.SetCookie}}}).Cookie(refreshCookieName)
	if err != nil {
		t.Fatal(err)
	}
	return &loginInput{CookieHeader: (&http.Cookie{Name: refreshCookieName, Value: cookie.Value}).String()}
}

func TestPasswordLoginIsLocalAcrossRefreshes(t *testing.T) {
	store, cloud := newFakeStore(), &fakeCloud{allowed: true}
	app := newTestApp(t, store, cloud)
	hash, err := bcrypt.GenerateFromPassword([]byte("pw"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	cloudID := int64(42)
	// Linked to the cloud too: a local login must still count as local.
	store.users[1] = persistence.User{ID: 1, Username: "alice", PasswordHash: string(hash), CloudUserID: &cloudID}

	username, password := "alice", "pw"
	res, err := app.Login(context.Background(), &loginInput{Body: &restmodels.LoginRequest{Username: &username, Password: &password}})
	if err != nil {
		t.Fatal(err)
	}
	if m := loginMethodOf(t, app, res); m != usertoken.LoginMethodLocal {
		t.Fatalf("password login method = %q, want local", m)
	}
	for n := 0; n < 2; n++ {
		res, err = app.Login(context.Background(), refreshFrom(t, res))
		if err != nil {
			t.Fatal(err)
		}
		if m := loginMethodOf(t, app, res); m != usertoken.LoginMethodLocal {
			t.Fatalf("refresh %d method = %q, want local", n+1, m)
		}
	}
	if cloud.accessCalls != 0 {
		t.Errorf("local session asked the cloud %d times", cloud.accessCalls)
	}
}

func TestCloudSessionIsCloudAcrossRefreshes(t *testing.T) {
	store, cloud := newFakeStore(), &fakeCloud{allowed: true}
	app := newTestApp(t, store, cloud)
	id := addCloudUser(store, 42)

	res, err := app.Login(context.Background(), refreshInput(t, app, id, time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	if m := loginMethodOf(t, app, res); m != usertoken.LoginMethodCloud {
		t.Fatalf("method = %q, want cloud", m)
	}
	res, err = app.Login(context.Background(), refreshFrom(t, res))
	if err != nil {
		t.Fatal(err)
	}
	if m := loginMethodOf(t, app, res); m != usertoken.LoginMethodCloud {
		t.Fatalf("method after refresh = %q, want cloud", m)
	}
}

func TestRefreshWithoutLocalMarkerIsUnknown(t *testing.T) {
	store, cloud := newFakeStore(), &fakeCloud{allowed: true}
	app := newTestApp(t, store, cloud)
	store.users[1] = persistence.User{ID: 1, Username: "alice", PasswordHash: "hash"}

	// A refresh token from before the lm claim existed.
	token, err := generateRefreshToken(app.refreshSecret, 1, time.Hour, time.Time{}, usertoken.LoginMethodUnknown)
	if err != nil {
		t.Fatal(err)
	}
	res, err := app.Login(context.Background(), &loginInput{CookieHeader: (&http.Cookie{Name: refreshCookieName, Value: token}).String()})
	if err != nil {
		t.Fatal(err)
	}
	if m := loginMethodOf(t, app, res); m != usertoken.LoginMethodUnknown {
		t.Fatalf("method = %q, want unknown", m)
	}
}
