package userwebapp

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/Kaese72/authentication/restmodels"
	"github.com/Kaese72/authentication/usertoken"
	"github.com/danielgtaylor/huma/v2"
)

func statusOf(err error) int {
	var se huma.StatusError
	if errors.As(err, &se) {
		return se.GetStatus()
	}
	return 0
}

// TestCreateUserRequiresLocalLogin: an admin whose session did not begin
// with a local password login cannot create a (password-bearing) user. The
// webApp has no persistence, so getting past the guard would panic.
func TestCreateUserRequiresLocalLogin(t *testing.T) {
	for _, method := range []usertoken.LoginMethod{
		usertoken.LoginMethodCloud,
		usertoken.LoginMethodUnknown,
		usertoken.LoginMethodImpersonation,
		usertoken.LoginMethodAPIToken,
	} {
		t.Run(string(method), func(t *testing.T) {
			ctx := usertoken.ContextWithLogin(context.Background(), 1, usertoken.AdminPermissions(), method)
			_, err := webApp{}.CreateUser(ctx, &struct {
				Body restmodels.CreateUserRequest
			}{Body: restmodels.CreateUserRequest{Username: "new", Password: "pw", Name: "N", Surname: "S"}})
			if statusOf(err) != http.StatusForbidden {
				t.Fatalf("got %v, want 403", err)
			}
		})
	}
}

func TestRequireLocalLoginAllowsLocal(t *testing.T) {
	ctx := usertoken.ContextWithLogin(context.Background(), 1, usertoken.AdminPermissions(), usertoken.LoginMethodLocal)
	if err := requireLocalLogin(ctx, "x"); err != nil {
		t.Fatalf("local login refused: %v", err)
	}
}
