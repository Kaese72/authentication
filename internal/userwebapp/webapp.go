package userwebapp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"database/sql"
	"encoding/hex"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/Kaese72/authentication/internal/cloudclient"
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
		LocalLogin:  u.PasswordHash != "",
		CloudLogin:  u.CloudUserID != nil,
		Permissions: toPermissionsResponse(u.Permissions),
	}
}

type webApp struct {
	persistence      persistence.UserManagementPersistenceDB
	publicKey        *rsa.PublicKey
	cloud            cloudclient.Client
	cloudStateExpiry time.Duration
}

func NewWebApp(p persistence.UserManagementPersistenceDB, publicKey *rsa.PublicKey, cloud cloudclient.Client, cloudStateExpiry time.Duration) webApp {
	return webApp{persistence: p, publicKey: publicKey, cloud: cloud, cloudStateExpiry: cloudStateExpiry}
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

func generateCloudState() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// cloudError maps a cloudclient error to the huma error to return. Mirrors
// restwebapp's own cloudError - kept separate rather than shared, since
// sharing it would mean one of these packages importing the other just for
// this.
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

// requireSelf reports whether ctx's caller (as placed there by
// usertoken.Middleware) is the same user as targetID. Linking a cloud account
// proves who completes the browser flow, not who asked for it to start, so
// only the user being linked may initiate or finish it - modify access to
// users (which would otherwise let an admin manage this like any other user
// field) is deliberately not enough here.
func requireSelf(ctx context.Context, targetID int64) error {
	callerID, ok := usertoken.UserID(ctx)
	if !ok || callerID != targetID {
		return huma.Error403Forbidden("only the user themselves may link a cloud account")
	}
	return nil
}

// LinkCloudStart begins linking id to a cloud account: it remembers a fresh
// one-time state scoped to id and returns the cloud URL the browser should be
// sent to. The cloud authenticates the user and sends the browser back to
// returnTo with a login code and the state; LinkCloudComplete finishes it.
func (app webApp) LinkCloudStart(ctx context.Context, input *struct {
	ID   int64 `path:"id"`
	Body restmodels.CloudLoginStartRequest
}) (*struct {
	Body restmodels.CloudLoginStartResponse
}, error) {
	if err := requireSelf(ctx, input.ID); err != nil {
		return nil, err
	}
	returnTo, err := url.Parse(input.Body.ReturnTo)
	if err != nil || (returnTo.Scheme != "http" && returnTo.Scheme != "https") || returnTo.Host == "" {
		return nil, huma.Error400BadRequest("returnTo must be an absolute http(s) URL")
	}
	state, err := generateCloudState()
	if err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to generate login state")
	}
	cloudURL, err := app.cloud.Start(ctx, state, input.Body.ReturnTo)
	if err != nil {
		return nil, cloudError(ctx, err)
	}
	if err := app.persistence.SaveCloudLinkState(ctx, state, time.Now().Add(app.cloudStateExpiry), input.ID); err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to save login state")
	}
	return &struct {
		Body restmodels.CloudLoginStartResponse
	}{Body: restmodels.CloudLoginStartResponse{State: state, CloudURL: cloudURL}}, nil
}

// LinkCloudComplete finishes linking id to a cloud account: it consumes the
// link state (which must have been created for this same id), redeems the
// login code with the cloud to learn who logged in, and links id to that
// cloud user. It fails with a conflict if another user is already linked to
// that cloud account.
func (app webApp) LinkCloudComplete(ctx context.Context, input *struct {
	ID   int64 `path:"id"`
	Body restmodels.CloudLoginCompleteRequest
}) (*struct {
	Body restmodels.UserResponse
}, error) {
	if err := requireSelf(ctx, input.ID); err != nil {
		return nil, err
	}
	stateUserID, ok, err := app.persistence.ConsumeCloudLinkState(ctx, input.Body.State)
	if err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to verify login state")
	}
	if !ok {
		return nil, huma.Error401Unauthorized("invalid or expired login state")
	}
	if stateUserID != input.ID {
		return nil, huma.Error400BadRequest("login state does not match this user")
	}
	cloudUser, err := app.cloud.Redeem(ctx, input.Body.Code)
	if err != nil {
		return nil, cloudError(ctx, err)
	}
	if err := app.persistence.LinkCloudUser(ctx, input.ID, cloudUser.ID); err != nil {
		if mysqlErr, ok := err.(*mysql.MySQLError); ok && mysqlErr.Number == 1062 {
			return nil, huma.Error409Conflict("this cloud account is already linked to another user")
		}
		if err == sql.ErrNoRows {
			return nil, huma.Error404NotFound("user not found")
		}
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to link cloud account")
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
