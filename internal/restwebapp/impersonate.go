package restwebapp

import (
	"context"
	"database/sql"
	"time"

	"github.com/Kaese72/authentication/internal/logging"
	"github.com/Kaese72/authentication/restmodels"
	"github.com/danielgtaylor/huma/v2"
)

// Impersonate mints a short-lived use token for input.ID, carrying that
// user's own real permissions (not the caller's), so a trusted service
// (e.g. the chatbot, authenticated as its own Kubernetes ServiceAccount via
// the internal listener's huemie-lib/k8sauth middleware -- see main.go) can
// act on another service as the actual human who triggered the current
// request, rather than as itself. Unlike Login, this issues no refresh
// cookie: the token is meant to be used once, immediately, and discarded.
// It is only ever reachable through the internal listener, never the public
// router, so there is no caller-permissions concept to check here -- the
// router-level middleware already restricted who can even reach this
// handler.
func (app webApp) Impersonate(ctx context.Context, input *struct {
	ID int64 `path:"id"`
}) (*struct {
	Body restmodels.ImpersonateResponse
}, error) {
	target, err := app.persistence.GetUserByID(ctx, input.ID)
	if err == sql.ErrNoRows {
		return nil, huma.Error404NotFound("user not found")
	}
	if err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to get user")
	}
	useToken, err := generateUseToken(app.privateKey, target.ID, app.impersonationTokenExpiry, target.Permissions)
	if err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("token generation failed")
	}
	logging.Info("issued impersonation token", ctx, map[string]interface{}{
		"targetId": target.ID,
	})
	return &struct {
		Body restmodels.ImpersonateResponse
	}{Body: restmodels.ImpersonateResponse{
		UseToken:  useToken,
		ExpiresAt: time.Now().Add(app.impersonationTokenExpiry),
	}}, nil
}
