package userwebapp

import (
	"context"
	"crypto/rsa"
	"database/sql"
	"strings"

	"github.com/Kaese72/authentication/internal/logging"
	"github.com/Kaese72/authentication/internal/persistence"
	"github.com/Kaese72/authentication/internal/restwebapp"
	"github.com/Kaese72/authentication/restmodels"
	"github.com/danielgtaylor/huma/v2"
	"github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
)

type webApp struct {
	persistence persistence.UserManagementPersistenceDB
	publicKey   *rsa.PublicKey
}

func NewWebApp(p persistence.UserManagementPersistenceDB, publicKey *rsa.PublicKey) webApp {
	return webApp{persistence: p, publicKey: publicKey}
}

func (app webApp) ListUsers(ctx context.Context, input *struct {
	Offset int `query:"offset" default:"0" minimum:"0" doc:"number of matching users to skip"`
	Limit  int `query:"limit" default:"50" minimum:"1" maximum:"200" doc:"maximum number of users to return"`
}) (*struct {
	TotalCount int `header:"X-Total-Count" doc:"total number of users, ignoring pagination"`
	Body       []restmodels.UserResponse
}, error) {
	users, total, err := app.persistence.ListUsers(ctx, restmodels.Pagination{Offset: input.Offset, Limit: input.Limit})
	if err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to list users")
	}
	resp := make([]restmodels.UserResponse, len(users))
	for i, u := range users {
		resp[i] = restmodels.UserResponse{ID: u.ID, Username: u.Username, Name: u.Name, Surname: u.Surname, Email: u.Email}
	}
	return &struct {
		TotalCount int `header:"X-Total-Count" doc:"total number of users, ignoring pagination"`
		Body       []restmodels.UserResponse
	}{TotalCount: total, Body: resp}, nil
}

func (app webApp) GetUser(ctx context.Context, input *struct {
	ID int64 `path:"id"`
}) (*struct {
	Body restmodels.UserResponse
}, error) {
	user, err := app.persistence.GetUserByID(ctx, input.ID)
	if err == sql.ErrNoRows {
		return nil, huma.Error404NotFound("user not found")
	}
	if err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to get user")
	}
	return &struct{ Body restmodels.UserResponse }{Body: restmodels.UserResponse{ID: user.ID, Username: user.Username, Name: user.Name, Surname: user.Surname, Email: user.Email}}, nil
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
	if err := app.persistence.CreateUser(ctx, input.Body.Username, string(hash), input.Body.Name, input.Body.Surname, input.Body.Email); err != nil {
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
	return &struct{ Body restmodels.UserResponse }{Body: restmodels.UserResponse{ID: user.ID, Username: user.Username, Name: user.Name, Surname: user.Surname, Email: user.Email}}, nil
}

func (app webApp) UpdateUser(ctx context.Context, input *struct {
	ID   int64 `path:"id"`
	Body restmodels.UpdateUserRequest
}) (*struct {
	Body restmodels.UserResponse
}, error) {
	if err := app.persistence.UpdateUser(ctx, input.ID, input.Body.Name, input.Body.Surname, input.Body.Email); err != nil {
		if err == sql.ErrNoRows {
			return nil, huma.Error404NotFound("user not found")
		}
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to update user")
	}
	user, err := app.persistence.GetUserByID(ctx, input.ID)
	if err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to retrieve updated user")
	}
	return &struct{ Body restmodels.UserResponse }{Body: restmodels.UserResponse{ID: user.ID, Username: user.Username, Name: user.Name, Surname: user.Surname, Email: user.Email}}, nil
}

func (app webApp) DeleteUser(ctx context.Context, input *struct {
	ID int64 `path:"id"`
}) (*struct{}, error) {
	err := app.persistence.DeleteUser(ctx, input.ID)
	if err == sql.ErrNoRows {
		return nil, huma.Error404NotFound("user not found")
	}
	if err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to delete user")
	}
	return &struct{}{}, nil
}

func (app webApp) UpdateMyPassword(ctx context.Context, input *struct {
	Authorization string `header:"Authorization"`
	Body          restmodels.ChangePasswordRequest
}) (*struct{}, error) {
	tokenString := strings.TrimSpace(strings.TrimPrefix(input.Authorization, "Bearer "))
	id, err := restwebapp.ValidateUseToken(app.publicKey, tokenString)
	if err != nil {
		return nil, huma.Error401Unauthorized("invalid or expired token")
	}

	user, err := app.persistence.GetUserByID(ctx, id)
	if err == sql.ErrNoRows {
		return nil, huma.Error404NotFound("user not found")
	}
	if err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to get user")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(input.Body.CurrentPassword)); err != nil {
		return nil, huma.Error401Unauthorized("current password is incorrect")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(input.Body.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to hash password")
	}
	if err := app.persistence.UpdatePassword(ctx, user.Username, string(hash)); err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to update password")
	}
	return &struct{}{}, nil
}
