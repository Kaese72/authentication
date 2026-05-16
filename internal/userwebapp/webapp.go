package userwebapp

import (
	"context"
	"database/sql"

	"github.com/Kaese72/authentication/internal/logging"
	"github.com/Kaese72/authentication/internal/persistence"
	"github.com/Kaese72/authentication/restmodels"
	"github.com/danielgtaylor/huma/v2"
	"github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
)

type webApp struct {
	persistence persistence.UserManagementPersistenceDB
}

func NewWebApp(p persistence.UserManagementPersistenceDB) webApp {
	return webApp{persistence: p}
}

func (app webApp) ListUsers(ctx context.Context, input *struct{}) (*struct {
	Body []restmodels.UserResponse
}, error) {
	users, err := app.persistence.ListUsers(ctx)
	if err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to list users")
	}
	resp := make([]restmodels.UserResponse, len(users))
	for i, u := range users {
		resp[i] = restmodels.UserResponse{ID: u.ID, Username: u.Username}
	}
	return &struct{ Body []restmodels.UserResponse }{Body: resp}, nil
}

func (app webApp) GetUser(ctx context.Context, input *struct {
	Username string `path:"username"`
}) (*struct {
	Body restmodels.UserResponse
}, error) {
	user, err := app.persistence.GetUserByUsername(ctx, input.Username)
	if err == sql.ErrNoRows {
		return nil, huma.Error404NotFound("user not found")
	}
	if err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to get user")
	}
	return &struct{ Body restmodels.UserResponse }{Body: restmodels.UserResponse{ID: user.ID, Username: user.Username}}, nil
}

func (app webApp) CreateUser(ctx context.Context, input *struct {
	Body restmodels.CreateUserRequest
}) (*struct {
	Body restmodels.UserResponse
}, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(input.Body.Password), bcrypt.DefaultCost)
	if err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to hash password")
	}
	if err := app.persistence.CreateUser(ctx, input.Body.Username, string(hash)); err != nil {
		if mysqlErr, ok := err.(*mysql.MySQLError); ok && mysqlErr.Number == 1062 {
			return nil, huma.Error409Conflict("username already exists")
		}
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to create user")
	}
	user, err := app.persistence.GetUserByUsername(ctx, input.Body.Username)
	if err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to retrieve created user")
	}
	return &struct{ Body restmodels.UserResponse }{Body: restmodels.UserResponse{ID: user.ID, Username: user.Username}}, nil
}

func (app webApp) DeleteUser(ctx context.Context, input *struct {
	Username string `path:"username"`
}) (*struct{}, error) {
	err := app.persistence.DeleteUser(ctx, input.Username)
	if err == sql.ErrNoRows {
		return nil, huma.Error404NotFound("user not found")
	}
	if err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to delete user")
	}
	return &struct{}{}, nil
}
