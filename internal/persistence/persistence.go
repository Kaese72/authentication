package persistence

import "context"

type User struct {
	ID           int64
	Username     string
	PasswordHash string
}

type AuthPersistenceDB interface {
	GetUserByUsername(ctx context.Context, username string) (User, error)
}

type SetupPersistenceDB interface {
	UserExists(ctx context.Context) (bool, error)
	CreateUser(ctx context.Context, username string, passwordHash string) error
}

type UserManagementPersistenceDB interface {
	ListUsers(ctx context.Context) ([]User, error)
	GetUserByID(ctx context.Context, id int64) (User, error)
	GetUserByUsername(ctx context.Context, username string) (User, error)
	CreateUser(ctx context.Context, username string, passwordHash string) error
	DeleteUser(ctx context.Context, id int64) error
	UpdatePassword(ctx context.Context, username string, passwordHash string) error
}
