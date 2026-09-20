package restwebapp

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/Kaese72/authentication/internal/cloudclient"
	"github.com/Kaese72/authentication/internal/logging"
	"github.com/Kaese72/authentication/internal/persistence"
	"github.com/Kaese72/authentication/restmodels"
	"github.com/danielgtaylor/huma/v2"
	"github.com/go-sql-driver/mysql"
)

func generateState() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func cloudError(ctx context.Context, err error) error {
	switch {
	case errors.Is(err, cloudclient.ErrNotConfigured):
		return huma.Error404NotFound("cloud login is not available")
	case errors.Is(err, cloudclient.ErrNotEnrolled):
		return huma.Error409Conflict("appliance is not enrolled with the cloud")
	case errors.Is(err, cloudclient.ErrRefused):
		return huma.Error401Unauthorized("cloud login refused")
	default:
		logging.ErrorErr(err, ctx)
		return huma.Error502BadGateway("failed to reach the cloud")
	}
}

// CloudStatus tells the login page whether to offer cloud login. Failing to
// find out is reported as "not available" rather than an error: the page
// must render either way.
func (app webApp) CloudStatus(ctx context.Context, input *struct{}) (*struct {
	Body restmodels.CloudLoginStatusResponse
}, error) {
	available, err := app.cloud.Available(ctx)
	if err != nil {
		logging.ErrorErr(err, ctx)
		available = false
	}
	return &struct {
		Body restmodels.CloudLoginStatusResponse
	}{Body: restmodels.CloudLoginStatusResponse{Available: available}}, nil
}

// CloudStart begins a cloud login: it remembers a fresh one-time state and
// returns the cloud URL the browser should be sent to. The cloud
// authenticates the user, checks they may access this appliance, and sends
// the browser back to returnTo with a login code and the state.
func (app webApp) CloudStart(ctx context.Context, input *struct {
	Body restmodels.CloudLoginStartRequest
}) (*struct {
	Body restmodels.CloudLoginStartResponse
}, error) {
	returnTo, err := url.Parse(input.Body.ReturnTo)
	if err != nil || (returnTo.Scheme != "http" && returnTo.Scheme != "https") || returnTo.Host == "" {
		return nil, huma.Error400BadRequest("returnTo must be an absolute http(s) URL")
	}
	state, err := generateState()
	if err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to generate login state")
	}
	cloudURL, err := app.cloud.Start(ctx, state, input.Body.ReturnTo)
	if err != nil {
		return nil, cloudError(ctx, err)
	}
	if err := app.persistence.SaveCloudLoginState(ctx, state, time.Now().Add(app.cloudStateExpiry)); err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to save login state")
	}
	return &struct {
		Body restmodels.CloudLoginStartResponse
	}{Body: restmodels.CloudLoginStartResponse{State: state, CloudURL: cloudURL}}, nil
}

// CloudComplete finishes a cloud login: it consumes the state, redeems the
// login code with the cloud to learn who logged in (the cloud only hands that
// out for a user who currently has access to this appliance), creates a local
// user for them if this is their first login, and issues the same token pair a
// password login would.
func (app webApp) CloudComplete(ctx context.Context, input *struct {
	Body restmodels.CloudLoginCompleteRequest
}) (*loginResult, error) {
	valid, err := app.persistence.ConsumeCloudLoginState(ctx, input.Body.State)
	if err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to verify login state")
	}
	if !valid {
		return nil, huma.Error401Unauthorized("invalid or expired login state")
	}
	cloudUser, err := app.cloud.Redeem(ctx, input.Body.Code)
	if err != nil {
		return nil, cloudError(ctx, err)
	}
	user, err := app.findOrCreateCloudUser(ctx, cloudUser)
	if err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to provision user")
	}
	return app.issueLogin(ctx, user.ID, time.Now())
}

func isDuplicate(err error) bool {
	var mysqlErr *mysql.MySQLError
	return errors.As(err, &mysqlErr) && mysqlErr.Number == 1062
}

// findOrCreateCloudUser returns the local user linked to the cloud user,
// creating one on first login and keeping the local copy of their profile in
// step with the cloud on later ones. Local users are matched on the cloud user
// id, never on username, so a cloud user cannot take over a local account of
// the same name; if the username is taken, they get a distinct one.
func (app webApp) findOrCreateCloudUser(ctx context.Context, cloudUser cloudclient.CloudUser) (persistence.User, error) {
	var email *string
	if cloudUser.Email != "" {
		email = &cloudUser.Email
	}

	user, err := app.persistence.GetUserByCloudUserID(ctx, cloudUser.ID)
	if err == nil {
		emailChanged := (user.Email == nil) != (email == nil) || (user.Email != nil && email != nil && *user.Email != *email)
		if user.Name != cloudUser.Name || user.Surname != cloudUser.Surname || emailChanged {
			if err := app.persistence.UpdateUser(ctx, user.ID, cloudUser.Name, cloudUser.Surname, email); err != nil {
				// The profile copy being stale must not block login.
				logging.ErrorErr(err, ctx)
			}
		}
		return user, nil
	}
	if err != sql.ErrNoRows {
		return persistence.User{}, err
	}

	err = app.persistence.CreateCloudUser(ctx, cloudUser.ID, cloudUser.Username, cloudUser.Name, cloudUser.Surname, email)
	if isDuplicate(err) {
		err = app.persistence.CreateCloudUser(ctx, cloudUser.ID, fmt.Sprintf("%s-cloud-%d", cloudUser.Username, cloudUser.ID), cloudUser.Name, cloudUser.Surname, email)
	}
	if err != nil {
		// A concurrent first login for the same cloud user may have won.
		if existing, getErr := app.persistence.GetUserByCloudUserID(ctx, cloudUser.ID); getErr == nil {
			return existing, nil
		}
		return persistence.User{}, err
	}
	return app.persistence.GetUserByCloudUserID(ctx, cloudUser.ID)
}
