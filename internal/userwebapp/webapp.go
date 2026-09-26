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
	"github.com/Kaese72/authentication/usertoken"
	"github.com/danielgtaylor/huma/v2"
	"github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
)

// requireUsersModify reports whether ctx's caller (as placed there by
// usertoken.Middleware) may manage other users' accounts and permissions,
// returning the huma error to return otherwise. Every mutating endpoint in
// this file calls it first; admins always pass.
func requireUsersModify(ctx context.Context) error {
	permissions, ok := usertoken.PermissionsFromContext(ctx)
	if !ok || !permissions.HasModify(usertoken.ResourceUsers) {
		return huma.Error403Forbidden("modify access to users is required")
	}
	return nil
}

// requireUsersView is requireUsersModify's read-only counterpart, for
// endpoints that only list or look up users.
func requireUsersView(ctx context.Context) error {
	permissions, ok := usertoken.PermissionsFromContext(ctx)
	if !ok || !permissions.HasView(usertoken.ResourceUsers) {
		return huma.Error403Forbidden("view access to users is required")
	}
	return nil
}

// requireAdmin reports whether ctx's caller is themselves an admin. Only
// SetUserAdmin calls this: modify access to users is not enough to grant or
// revoke admin, since that would let a non-admin promote themselves (or
// anyone else) to admin.
func requireAdmin(ctx context.Context) error {
	permissions, ok := usertoken.PermissionsFromContext(ctx)
	if !ok || !permissions.Admin() {
		return huma.Error403Forbidden("admin is required")
	}
	return nil
}

// validResource reports whether code is one of the resource codes
// usertoken.Resources defines.
func validResource(code string) bool {
	for _, resource := range usertoken.KnownResources {
		if resource == code {
			return true
		}
	}
	return false
}

// toPermissionsResponse renders p in the REST shape, listing every known
// resource so a permissions editor always has a fixed set of rows.
func toPermissionsResponse(p usertoken.Permissions) restmodels.PermissionsResponse {
	if p.Admin() {
		return restmodels.PermissionsResponse{Admin: true}
	}
	resources := make(map[string]restmodels.ResourcePermission, len(usertoken.KnownResources))
	for _, resource := range usertoken.KnownResources {
		resources[resource] = restmodels.ResourcePermission{View: p.HasView(resource), Modify: p.HasModify(resource)}
	}
	return restmodels.PermissionsResponse{Resources: resources}
}

// grantFromResourcePermission converts the REST request shape for a single
// resource into a usertoken.ResourceGrant, for persisting.
func grantFromResourcePermission(rp restmodels.ResourcePermission) usertoken.ResourceGrant {
	var grant usertoken.ResourceGrant
	if rp.View {
		grant.View = "*"
	}
	if rp.Modify {
		grant.Modify = "*"
	}
	return grant
}

// ListResources returns the catalog of resources permissions can be granted
// for, so a permissions editor can be built without hardcoding it. Any
// authenticated user may call this - it is metadata, not a grant.
func (app webApp) ListResources(ctx context.Context, input *struct{}) (*struct {
	Body []restmodels.ResourceDefinition
}, error) {
	resp := make([]restmodels.ResourceDefinition, len(usertoken.Resources))
	for i, r := range usertoken.Resources {
		resp[i] = restmodels.ResourceDefinition{Code: r.Code, Name: r.Name}
	}
	return &struct {
		Body []restmodels.ResourceDefinition
	}{Body: resp}, nil
}

func toUserResponse(u persistence.User) restmodels.UserResponse {
	return restmodels.UserResponse{
		ID:          u.ID,
		Username:    u.Username,
		Name:        u.Name,
		Surname:     u.Surname,
		Email:       u.Email,
		Permissions: toPermissionsResponse(u.Permissions),
	}
}

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
	if err := requireUsersView(ctx); err != nil {
		return nil, err
	}
	users, total, err := app.persistence.ListUsers(ctx, restmodels.Pagination{Offset: input.Offset, Limit: input.Limit})
	if err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to list users")
	}
	resp := make([]restmodels.UserResponse, len(users))
	for i, u := range users {
		resp[i] = toUserResponse(u)
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
	if err := requireUsersView(ctx); err != nil {
		return nil, err
	}
	user, err := app.persistence.GetUserByID(ctx, input.ID)
	if err == sql.ErrNoRows {
		return nil, huma.Error404NotFound("user not found")
	}
	if err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to get user")
	}
	return &struct{ Body restmodels.UserResponse }{Body: toUserResponse(user)}, nil
}

// CreateUser creates a new user with no permissions - an admin, or someone
// with modify access to users, must grant them any via UpdateUserPermissions
// afterwards.
func (app webApp) CreateUser(ctx context.Context, input *struct {
	Body restmodels.CreateUserRequest
}) (*struct {
	Body restmodels.UserResponse
}, error) {
	if err := requireUsersModify(ctx); err != nil {
		return nil, err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(input.Body.Password), bcrypt.DefaultCost)
	if err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to hash password")
	}
	if err := app.persistence.CreateUser(ctx, input.Body.Username, string(hash), input.Body.Name, input.Body.Surname, input.Body.Email, usertoken.Permissions{}); err != nil {
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
	return &struct{ Body restmodels.UserResponse }{Body: toUserResponse(user)}, nil
}

func (app webApp) UpdateUser(ctx context.Context, input *struct {
	ID   int64 `path:"id"`
	Body restmodels.UpdateUserRequest
}) (*struct {
	Body restmodels.UserResponse
}, error) {
	if err := requireUsersModify(ctx); err != nil {
		return nil, err
	}
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
	return &struct{ Body restmodels.UserResponse }{Body: toUserResponse(user)}, nil
}

// UpdateUserPermissions replaces id's grant for a single resource, leaving
// its other resources and its admin flag untouched - one call per resource,
// rather than one call replacing every resource at once.
func (app webApp) UpdateUserPermissions(ctx context.Context, input *struct {
	ID       int64  `path:"id"`
	Resource string `path:"resource" doc:"a resource code from GET /permissions/resources"`
	Body     restmodels.ResourcePermission
}) (*struct {
	Body restmodels.UserResponse
}, error) {
	if err := requireUsersModify(ctx); err != nil {
		return nil, err
	}
	if !validResource(input.Resource) {
		return nil, huma.Error400BadRequest("unknown resource")
	}
	if err := app.persistence.UpdatePermissions(ctx, input.ID, input.Resource, grantFromResourcePermission(input.Body)); err != nil {
		if err == sql.ErrNoRows {
			return nil, huma.Error404NotFound("user not found")
		}
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to update permissions")
	}
	user, err := app.persistence.GetUserByID(ctx, input.ID)
	if err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to retrieve updated user")
	}
	return &struct{ Body restmodels.UserResponse }{Body: toUserResponse(user)}, nil
}

// SetUserAdmin grants or revokes id's admin flag. Unlike UpdateUserPermissions,
// this requires the caller to already be an admin themselves.
func (app webApp) SetUserAdmin(ctx context.Context, input *struct {
	ID   int64 `path:"id"`
	Body restmodels.SetAdminRequest
}) (*struct {
	Body restmodels.UserResponse
}, error) {
	if err := requireAdmin(ctx); err != nil {
		return nil, err
	}
	if err := app.persistence.SetAdmin(ctx, input.ID, input.Body.Admin); err != nil {
		if err == sql.ErrNoRows {
			return nil, huma.Error404NotFound("user not found")
		}
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to update admin status")
	}
	user, err := app.persistence.GetUserByID(ctx, input.ID)
	if err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to retrieve updated user")
	}
	return &struct{ Body restmodels.UserResponse }{Body: toUserResponse(user)}, nil
}

func (app webApp) DeleteUser(ctx context.Context, input *struct {
	ID int64 `path:"id"`
}) (*struct{}, error) {
	if err := requireUsersModify(ctx); err != nil {
		return nil, err
	}
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
	id, _, err := restwebapp.ValidateUseToken(app.publicKey, tokenString)
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
	// A local password would be a way in that never re-checks cloud access.
	if user.CloudUserID != nil {
		return nil, huma.Error403Forbidden("cloud users sign in through the cloud and have no local password")
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
