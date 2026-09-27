package persistence

import (
	"context"
	"time"

	"github.com/Kaese72/authentication/usertoken"
	"github.com/Kaese72/huemie-lib/query"
)

type User struct {
	ID       int64
	Username string
	Name     string
	Surname  string
	Email    *string
	// PasswordHash is empty for cloud users, who have no local password.
	PasswordHash string
	// CloudUserID is set for users who log in with their Humi Cloud account.
	CloudUserID *int64
	// Permissions is what gets embedded in this user's use tokens: the admin
	// flag and/or their per-resource grants.
	Permissions usertoken.Permissions
}

type AuthPersistenceDB interface {
	GetUserByUsername(ctx context.Context, username string) (User, error)
	GetUserByID(ctx context.Context, id int64) (User, error)
	GetUserByCloudUserID(ctx context.Context, cloudUserID int64) (User, error)
	// CreateCloudUser creates a local user for a cloud user, with no password
	// and no permissions - an existing admin must grant them any.
	CreateCloudUser(ctx context.Context, cloudUserID int64, username string, name string, surname string, email *string) error
	UpdateUser(ctx context.Context, id int64, name string, surname string, email *string) error

	// SaveCloudLoginState remembers a state value until expiresAt. Expired
	// states are pruned as a side effect.
	SaveCloudLoginState(ctx context.Context, state string, expiresAt time.Time) error
	// ConsumeCloudLoginState deletes state and reports whether it existed and
	// had not expired, so a state can be used at most once.
	ConsumeCloudLoginState(ctx context.Context, state string) (bool, error)
}

type SetupPersistenceDB interface {
	UserExists(ctx context.Context) (bool, error)
	// CreateUser creates the appliance's first user with the given
	// permissions. Setup always grants this user admin - there is otherwise
	// no way for anyone to become admin.
	CreateUser(ctx context.Context, username string, passwordHash string, name string, surname string, email *string, permissions usertoken.Permissions) error
}

type UserManagementPersistenceDB interface {
	// ListUsers returns the page of users matching filters and ordered by
	// sorts (or the implementation's default order if sorts is empty), along
	// with the total number of users matching filters (ignoring pagination).
	ListUsers(ctx context.Context, filters []query.Filter, sorts []query.Sort, pagination query.Pagination) ([]User, int, error)
	GetUserByID(ctx context.Context, id int64) (User, error)
	GetUserByUsername(ctx context.Context, username string) (User, error)
	// CreateUser creates a new user with the given permissions.
	CreateUser(ctx context.Context, username string, passwordHash string, name string, surname string, email *string, permissions usertoken.Permissions) error
	UpdateUser(ctx context.Context, id int64, name string, surname string, email *string) error
	// UpdatePermissions replaces id's grant for a single resource, leaving
	// its other resources and its admin flag untouched. An empty grant (both
	// View and Modify unset) revokes that resource entirely. See SetAdmin,
	// the only way to grant or revoke admin.
	UpdatePermissions(ctx context.Context, id int64, resource string, grant usertoken.ResourceGrant) error
	// SetAdmin grants or revokes id's admin flag. Granting clears any
	// per-resource grants, since they become moot while admin; revoking
	// leaves the user with none, to be reassigned explicitly.
	SetAdmin(ctx context.Context, id int64, admin bool) error
	DeleteUser(ctx context.Context, id int64) error
	UpdatePassword(ctx context.Context, username string, passwordHash string) error

	// SaveCloudLinkState remembers a one-time state for linking id to
	// whichever cloud account the browser completes login as, until
	// expiresAt. Expired states of either kind (login or link) are pruned as
	// a side effect.
	SaveCloudLinkState(ctx context.Context, state string, expiresAt time.Time, id int64) error
	// ConsumeCloudLinkState deletes a link state and reports the user id it
	// was saved for, so a state can be used at most once. ok is false if no
	// matching, unexpired link state exists.
	ConsumeCloudLinkState(ctx context.Context, state string) (id int64, ok bool, err error)
	// LinkCloudUser links id to a cloud user id, so they can also log in
	// through the cloud alongside any existing local password. Returns a
	// duplicate-key error (see go-sql-driver/mysql's MySQLError, number 1062)
	// if another user is already linked to that cloud user id.
	LinkCloudUser(ctx context.Context, id int64, cloudUserID int64) error
}
