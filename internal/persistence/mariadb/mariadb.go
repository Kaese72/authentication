package mariadb

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/Kaese72/authentication/internal/config"
	"github.com/Kaese72/authentication/internal/logging"
	"github.com/Kaese72/authentication/internal/persistence"
	"github.com/Kaese72/authentication/restmodels"
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

// userColumns is the column list scanUser expects. passwordHash is NULL for
// cloud users and is surfaced as the empty string.
const userColumns = "id, username, name, surname, email, COALESCE(passwordHash, ''), cloudUserId"

func scanUser(row interface{ Scan(...any) error }) (persistence.User, error) {
	var user persistence.User
	var cloudUserID sql.NullInt64
	if err := row.Scan(&user.ID, &user.Username, &user.Name, &user.Surname, &user.Email, &user.PasswordHash, &cloudUserID); err != nil {
		return persistence.User{}, err
	}
	if cloudUserID.Valid {
		user.CloudUserID = &cloudUserID.Int64
	}
	return user, nil
}

func (m mariadbPersistence) GetUserByUsername(ctx context.Context, username string) (persistence.User, error) {
	return scanUser(m.db.QueryRowContext(ctx, "SELECT "+userColumns+" FROM users WHERE username = ?", username))
}

func (m mariadbPersistence) GetUserByID(ctx context.Context, id int64) (persistence.User, error) {
	return scanUser(m.db.QueryRowContext(ctx, "SELECT "+userColumns+" FROM users WHERE id = ?", id))
}

func (m mariadbPersistence) GetUserByCloudUserID(ctx context.Context, cloudUserID int64) (persistence.User, error) {
	return scanUser(m.db.QueryRowContext(ctx, "SELECT "+userColumns+" FROM users WHERE cloudUserId = ?", cloudUserID))
}

func (m mariadbPersistence) CreateCloudUser(ctx context.Context, cloudUserID int64, username string, name string, surname string, email *string) error {
	_, err := m.db.ExecContext(ctx, "INSERT INTO users (username, passwordHash, name, surname, email, cloudUserId) VALUES (?, NULL, ?, ?, ?, ?)", username, name, surname, email, cloudUserID)
	return err
}

func (m mariadbPersistence) SaveCloudLoginState(ctx context.Context, state string, expiresAt time.Time) error {
	if _, err := m.db.ExecContext(ctx, "DELETE FROM cloudLoginStates WHERE expiresAt < ?", time.Now().UTC()); err != nil {
		return err
	}
	_, err := m.db.ExecContext(ctx, "INSERT INTO cloudLoginStates (state, expiresAt) VALUES (?, ?)", state, expiresAt.UTC())
	return err
}

func (m mariadbPersistence) ConsumeCloudLoginState(ctx context.Context, state string) (bool, error) {
	result, err := m.db.ExecContext(ctx, "DELETE FROM cloudLoginStates WHERE state = ? AND expiresAt > ?", state, time.Now().UTC())
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	return n == 1, nil
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

// paginationClause returns the SQL "LIMIT ? OFFSET ?" fragment and its arguments
// for the given pagination. A zero Limit means unbounded, in which case no
// clause is applied.
func paginationClause(pagination restmodels.Pagination) (string, []any) {
	if pagination.Limit <= 0 {
		return "", nil
	}
	offset := pagination.Offset
	if offset < 0 {
		offset = 0
	}
	return " LIMIT ? OFFSET ?", []any{pagination.Limit, offset}
}

// countRows executes "SELECT COUNT(*) FROM <table>" and returns the total
// number of rows, ignoring pagination.
func countRows(ctx context.Context, db *sql.DB, table string) (int, error) {
	var total int
	row := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+table)
	if err := row.Scan(&total); err != nil {
		return 0, err
	}
	return total, nil
}

func (m mariadbPersistence) ListUsers(ctx context.Context, pagination restmodels.Pagination) ([]persistence.User, int, error) {
	total, err := countRows(ctx, m.db, "users")
	if err != nil {
		return nil, 0, err
	}
	query := "SELECT id, username, name, surname, email FROM users ORDER BY username"
	limitClause, limitArgs := paginationClause(pagination)
	query += limitClause
	rows, err := m.db.QueryContext(ctx, query, limitArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var users []persistence.User
	for rows.Next() {
		var user persistence.User
		if err := rows.Scan(&user.ID, &user.Username, &user.Name, &user.Surname, &user.Email); err != nil {
			return nil, 0, err
		}
		users = append(users, user)
	}
	return users, total, rows.Err()
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
