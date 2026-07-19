package setupwebapp

import (
	"context"

	"github.com/Kaese72/authentication/internal/logging"
	"github.com/Kaese72/authentication/internal/persistence"
	"github.com/Kaese72/authentication/restmodels"
	"github.com/danielgtaylor/huma/v2"
	"golang.org/x/crypto/bcrypt"
)

type webApp struct {
	persistence persistence.SetupPersistenceDB
}

func NewWebApp(p persistence.SetupPersistenceDB) webApp {
	return webApp{persistence: p}
}

func (app webApp) SetupStatus(ctx context.Context, input *struct{}) (*struct {
	Body restmodels.SetupStatus
}, error) {
	userExists, err := app.persistence.UserExists(ctx)
	if err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to query setup status")
	}
	return &struct{ Body restmodels.SetupStatus }{
		Body: restmodels.SetupStatus{User: userExists},
	}, nil
}

func (app webApp) SetupUser(ctx context.Context, input *struct {
	Body restmodels.SetupUserRequest
}) (*struct{}, error) {
	userExists, err := app.persistence.UserExists(ctx)
	if err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to query setup status")
	}
	if userExists {
		return nil, huma.Error400BadRequest("user setup is already done")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(input.Body.Password), bcrypt.DefaultCost)
	if err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to hash password")
	}

	if err := app.persistence.CreateUser(ctx, input.Body.Username, string(hash), input.Body.Name, input.Body.Surname, input.Body.Email); err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to create user")
	}
	return &struct{}{}, nil
}
