package mariadb

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/Kaese72/authentication/internal/config"
	"github.com/Kaese72/authentication/internal/logging"
	"github.com/Kaese72/authentication/internal/persistence"
	"go.elastic.co/apm/module/apmsql"
)

var _ persistence.UserManagementPersistenceDB = mariadbPersistence{}

type mariadbPersistence struct {
	db *sql.DB
}

func NewMariadbPersistence(conf config.DatabaseConfig) (mariadbPersistence, error) {
	db, err := apmsql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?parseTime=true&loc=UTC", conf.User, conf.Password, conf.Host, conf.Port, conf.Database))
	if err != nil {
		logging.Fatal(err.Error(), context.Background())
		return mariadbPersistence{}, err
	}
	return mariadbPersistence{db: db}, nil
}

func (m mariadbPersistence) GetUserByUsername(ctx context.Context, username string) (persistence.User, error) {
	row := m.db.QueryRowContext(ctx, "SELECT id, username, name, surname, email, passwordHash FROM users WHERE username = ?", username)
	var user persistence.User
	err := row.Scan(&user.ID, &user.Username, &user.Name, &user.Surname, &user.Email, &user.PasswordHash)
	if err != nil {
		return persistence.User{}, err
	}
	return user, nil
}

func (m mariadbPersistence) GetUserByID(ctx context.Context, id int64) (persistence.User, error) {
	row := m.db.QueryRowContext(ctx, "SELECT id, username, name, surname, email, passwordHash FROM users WHERE id = ?", id)
	var user persistence.User
	err := row.Scan(&user.ID, &user.Username, &user.Name, &user.Surname, &user.Email, &user.PasswordHash)
	if err != nil {
		return persistence.User{}, err
	}
	return user, nil
}

func (m mariadbPersistence) UserExists(ctx context.Context) (bool, error) {
	var count int
	err := m.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM users").Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func (m mariadbPersistence) CreateUser(ctx context.Context, username string, passwordHash string, name string, surname string, email *string) error {
	_, err := m.db.ExecContext(ctx, "INSERT INTO users (username, passwordHash, name, surname, email) VALUES (?, ?, ?, ?, ?)", username, passwordHash, name, surname, email)
	return err
}

func (m mariadbPersistence) UpdateUser(ctx context.Context, id int64, name string, surname string, email *string) error {
	result, err := m.db.ExecContext(ctx, "UPDATE users SET name = ?, surname = ?, email = ? WHERE id = ?", name, surname, email, id)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (m mariadbPersistence) ListUsers(ctx context.Context) ([]persistence.User, error) {
	rows, err := m.db.QueryContext(ctx, "SELECT id, username, name, surname, email FROM users ORDER BY username")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []persistence.User
	for rows.Next() {
		var user persistence.User
		if err := rows.Scan(&user.ID, &user.Username, &user.Name, &user.Surname, &user.Email); err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	return users, rows.Err()
}

func (m mariadbPersistence) DeleteUser(ctx context.Context, id int64) error {
	result, err := m.db.ExecContext(ctx, "DELETE FROM users WHERE id = ?", id)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (m mariadbPersistence) UpdatePassword(ctx context.Context, username string, passwordHash string) error {
	result, err := m.db.ExecContext(ctx, "UPDATE users SET passwordHash = ? WHERE username = ?", passwordHash, username)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}
