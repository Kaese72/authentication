package mariadb

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/Kaese72/authentication/internal/config"
	"github.com/Kaese72/authentication/internal/logging"
	"github.com/Kaese72/authentication/internal/persistence"
	"github.com/Kaese72/authentication/restmodels"
	"github.com/Kaese72/authentication/usertoken"
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

// userColumns is the column list scanUserBase expects. passwordHash is NULL
// for cloud users and is surfaced as the empty string. It does not carry
// resource grants - those live in userPermissions and are attached
// separately, since a single row can't hold a variable number of them.
const userColumns = "id, username, name, surname, email, COALESCE(passwordHash, ''), cloudUserId, isAdmin"

// scanUserBase scans everything about a user except their resource grants.
// If isAdmin is set, user.Permissions is already complete (AdminPermissions
// makes any resource grants moot); otherwise the caller must attach them,
// e.g. via attachPermissions or loadResourceGrants.
func scanUserBase(row interface{ Scan(...any) error }) (persistence.User, error) {
	var user persistence.User
	var cloudUserID sql.NullInt64
	var isAdmin bool
	if err := row.Scan(&user.ID, &user.Username, &user.Name, &user.Surname, &user.Email, &user.PasswordHash, &cloudUserID, &isAdmin); err != nil {
		return persistence.User{}, err
	}
	if cloudUserID.Valid {
		user.CloudUserID = &cloudUserID.Int64
	}
	if isAdmin {
		user.Permissions = usertoken.AdminPermissions()
	}
	return user, nil
}

// loadResourceGrants returns each of userIDs' resource grants, keyed by user
// ID then resource code. A user with no grants at all (including every admin,
// whose rows are moot and are not expected to exist) is simply absent from
// the result rather than mapped to an empty map.
func (m mariadbPersistence) loadResourceGrants(ctx context.Context, userIDs []int64) (map[int64]map[string]usertoken.ResourceGrant, error) {
	result := map[int64]map[string]usertoken.ResourceGrant{}
	if len(userIDs) == 0 {
		return result, nil
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(userIDs)), ",")
	args := make([]any, len(userIDs))
	for i, id := range userIDs {
		args[i] = id
	}
	rows, err := m.db.QueryContext(ctx, "SELECT userId, resource, viewAccess, modifyAccess FROM userPermissions WHERE userId IN ("+placeholders+")", args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var userID int64
		var resource string
		var view, modify bool
		if err := rows.Scan(&userID, &resource, &view, &modify); err != nil {
			return nil, err
		}
		var grant usertoken.ResourceGrant
		if view {
			grant.View = "*"
		}
		if modify {
			grant.Modify = "*"
		}
		if result[userID] == nil {
			result[userID] = map[string]usertoken.ResourceGrant{}
		}
		result[userID][resource] = grant
	}
	return result, rows.Err()
}

// attachPermissions fills in user.Permissions with its resource grants,
// unless it is already admin (in which case there is nothing to add).
func (m mariadbPersistence) attachPermissions(ctx context.Context, user persistence.User) (persistence.User, error) {
	if user.Permissions.Admin() {
		return user, nil
	}
	grants, err := m.loadResourceGrants(ctx, []int64{user.ID})
	if err != nil {
		return persistence.User{}, err
	}
	user.Permissions = usertoken.NewPermissions(grants[user.ID])
	return user, nil
}

func (m mariadbPersistence) getUser(ctx context.Context, row interface{ Scan(...any) error }) (persistence.User, error) {
	user, err := scanUserBase(row)
	if err != nil {
		return persistence.User{}, err
	}
	return m.attachPermissions(ctx, user)
}

func (m mariadbPersistence) GetUserByUsername(ctx context.Context, username string) (persistence.User, error) {
	return m.getUser(ctx, m.db.QueryRowContext(ctx, "SELECT "+userColumns+" FROM users WHERE username = ?", username))
}

func (m mariadbPersistence) GetUserByID(ctx context.Context, id int64) (persistence.User, error) {
	return m.getUser(ctx, m.db.QueryRowContext(ctx, "SELECT "+userColumns+" FROM users WHERE id = ?", id))
}

func (m mariadbPersistence) GetUserByCloudUserID(ctx context.Context, cloudUserID int64) (persistence.User, error) {
	return m.getUser(ctx, m.db.QueryRowContext(ctx, "SELECT "+userColumns+" FROM users WHERE cloudUserId = ?", cloudUserID))
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

// execer is satisfied by both *sql.DB and *sql.Tx, so replaceResourceGrants
// can run either standalone or as part of a larger transaction.
type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// replaceResourceGrants overwrites userID's resource grants to match
// permissions exactly, leaving none behind for an admin (whose grants would
// be moot anyway).
func replaceResourceGrants(ctx context.Context, ex execer, userID int64, permissions usertoken.Permissions) error {
	if _, err := ex.ExecContext(ctx, "DELETE FROM userPermissions WHERE userId = ?", userID); err != nil {
		return err
	}
	for resource, grant := range permissions.Resources() {
		if _, err := ex.ExecContext(ctx, "INSERT INTO userPermissions (userId, resource, viewAccess, modifyAccess) VALUES (?, ?, ?, ?)", userID, resource, grant.View != "", grant.Modify != ""); err != nil {
			return err
		}
	}
	return nil
}

func (m mariadbPersistence) CreateUser(ctx context.Context, username string, passwordHash string, name string, surname string, email *string, permissions usertoken.Permissions) error {
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, "INSERT INTO users (username, passwordHash, name, surname, email, isAdmin) VALUES (?, ?, ?, ?, ?, ?)", username, passwordHash, name, surname, email, permissions.Admin())
	if err != nil {
		return err
	}
	userID, err := result.LastInsertId()
	if err != nil {
		return err
	}
	if err := replaceResourceGrants(ctx, tx, userID, permissions); err != nil {
		return err
	}
	return tx.Commit()
}

// userExists is a helper for the write paths below, which cannot rely on
// RowsAffected to detect a missing user: an UPDATE that changes nothing
// because the value already matches also reports 0 rows affected, and a
// DELETE/INSERT into userPermissions alone would not fail for a user that
// does not exist (an empty grant, for instance, only deletes, never inserts,
// so it never touches the foreign key).
func userExists(ctx context.Context, tx *sql.Tx, id int64) (bool, error) {
	var exists int64
	err := tx.QueryRowContext(ctx, "SELECT id FROM users WHERE id = ?", id).Scan(&exists)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// UpdatePermissions replaces a single resource's grant for id, leaving its
// other resources and its admin flag untouched. An empty grant (both View
// and Modify unset) removes the resource's row entirely, equivalent to it
// never having been granted.
func (m mariadbPersistence) UpdatePermissions(ctx context.Context, id int64, resource string, grant usertoken.ResourceGrant) error {
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	exists, err := userExists(ctx, tx, id)
	if err != nil {
		return err
	}
	if !exists {
		return sql.ErrNoRows
	}
	if grant.View == "" && grant.Modify == "" {
		if _, err := tx.ExecContext(ctx, "DELETE FROM userPermissions WHERE userId = ? AND resource = ?", id, resource); err != nil {
			return err
		}
		return tx.Commit()
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO userPermissions (userId, resource, viewAccess, modifyAccess) VALUES (?, ?, ?, ?)
		 ON DUPLICATE KEY UPDATE viewAccess = VALUES(viewAccess), modifyAccess = VALUES(modifyAccess)`,
		id, resource, grant.View != "", grant.Modify != ""); err != nil {
		return err
	}
	return tx.Commit()
}

// SetAdmin grants or revokes id's admin flag. Granting clears any
// per-resource grants, since they become moot while admin; revoking leaves
// the user with none, to be reassigned explicitly via UpdatePermissions.
func (m mariadbPersistence) SetAdmin(ctx context.Context, id int64, admin bool) error {
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	exists, err := userExists(ctx, tx, id)
	if err != nil {
		return err
	}
	if !exists {
		return sql.ErrNoRows
	}
	if _, err := tx.ExecContext(ctx, "UPDATE users SET isAdmin = ? WHERE id = ?", admin, id); err != nil {
		return err
	}
	if admin {
		if _, err := tx.ExecContext(ctx, "DELETE FROM userPermissions WHERE userId = ?", id); err != nil {
			return err
		}
	}
	return tx.Commit()
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
	query := "SELECT id, username, name, surname, email, isAdmin FROM users ORDER BY username"
	limitClause, limitArgs := paginationClause(pagination)
	query += limitClause
	rows, err := m.db.QueryContext(ctx, query, limitArgs...)
	if err != nil {
		return nil, 0, err
	}
	var users []persistence.User
	var nonAdminIDs []int64
	for rows.Next() {
		var user persistence.User
		var isAdmin bool
		if err := rows.Scan(&user.ID, &user.Username, &user.Name, &user.Surname, &user.Email, &isAdmin); err != nil {
			rows.Close()
			return nil, 0, err
		}
		if isAdmin {
			user.Permissions = usertoken.AdminPermissions()
		} else {
			nonAdminIDs = append(nonAdminIDs, user.ID)
		}
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, 0, err
	}
	rows.Close()

	grants, err := m.loadResourceGrants(ctx, nonAdminIDs)
	if err != nil {
		return nil, 0, err
	}
	for i := range users {
		if !users[i].Permissions.Admin() {
			users[i].Permissions = usertoken.NewPermissions(grants[users[i].ID])
		}
	}
	return users, total, nil
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
