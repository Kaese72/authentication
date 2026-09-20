package persistence

import (
	"context"
	"time"

	"github.com/Kaese72/authentication/restmodels"
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
}

type AuthPersistenceDB interface {
	GetUserByUsername(ctx context.Context, username string) (User, error)
	GetUserByID(ctx context.Context, id int64) (User, error)
	GetUserByCloudUserID(ctx context.Context, cloudUserID int64) (User, error)
	// CreateCloudUser creates a local user for a cloud user, with no password.
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
	CreateUser(ctx context.Context, username string, passwordHash string, name string, surname string, email *string) error
}

type UserManagementPersistenceDB interface {
	// ListUsers returns the page of users, along with the total number of
	// users (ignoring pagination).
	ListUsers(ctx context.Context, pagination restmodels.Pagination) ([]User, int, error)
	GetUserByID(ctx context.Context, id int64) (User, error)
	GetUserByUsername(ctx context.Context, username string) (User, error)
	CreateUser(ctx context.Context, username string, passwordHash string, name string, surname string, email *string) error
	UpdateUser(ctx context.Context, id int64, name string, surname string, email *string) error
	DeleteUser(ctx context.Context, id int64) error
	UpdatePassword(ctx context.Context, username string, passwordHash string) error
}
