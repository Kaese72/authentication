package mariadb

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/Kaese72/authentication/internal/persistence"
)

var _ persistence.APITokenPersistenceDB = mariadbPersistence{}

const apiTokenColumns = "id, userId, publicId, secretHash, name, permissions, expiresAt, lastUsedAt, createdAt"

func scanAPIToken(row interface{ Scan(...any) error }) (persistence.APIToken, error) {
	var token persistence.APIToken
	var permissions []byte
	var expiresAt, lastUsedAt sql.NullTime
	if err := row.Scan(&token.ID, &token.UserID, &token.PublicID, &token.SecretHash, &token.Name, &permissions, &expiresAt, &lastUsedAt, &token.CreatedAt); err != nil {
		return persistence.APIToken{}, err
	}
	if err := json.Unmarshal(permissions, &token.Permissions); err != nil {
		return persistence.APIToken{}, err
	}
	if expiresAt.Valid {
		token.ExpiresAt = &expiresAt.Time
	}
	if lastUsedAt.Valid {
		token.LastUsedAt = &lastUsedAt.Time
	}
	return token, nil
}

func nullableUTC(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.UTC()
}

func (m mariadbPersistence) CreateAPIToken(ctx context.Context, token persistence.APIToken) (int64, error) {
	permissions, err := json.Marshal(token.Permissions)
	if err != nil {
		return 0, err
	}
	result, err := m.db.ExecContext(ctx,
		"INSERT INTO apiTokens (userId, publicId, secretHash, name, permissions, expiresAt, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?)",
		token.UserID, token.PublicID, token.SecretHash, token.Name, permissions, nullableUTC(token.ExpiresAt), token.CreatedAt.UTC())
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

func (m mariadbPersistence) ListAPITokens(ctx context.Context, userID int64) ([]persistence.APIToken, error) {
	rows, err := m.db.QueryContext(ctx, "SELECT "+apiTokenColumns+" FROM apiTokens WHERE userId = ? ORDER BY createdAt, id", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	tokens := []persistence.APIToken{}
	for rows.Next() {
		token, err := scanAPIToken(rows)
		if err != nil {
			return nil, err
		}
		tokens = append(tokens, token)
	}
	return tokens, rows.Err()
}

func (m mariadbPersistence) DeleteAPIToken(ctx context.Context, userID int64, id int64) error {
	result, err := m.db.ExecContext(ctx, "DELETE FROM apiTokens WHERE id = ? AND userId = ?", id, userID)
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

func (m mariadbPersistence) GetAPITokenByPublicID(ctx context.Context, publicID string) (persistence.APIToken, error) {
	return scanAPIToken(m.db.QueryRowContext(ctx, "SELECT "+apiTokenColumns+" FROM apiTokens WHERE publicId = ?", publicID))
}

func (m mariadbPersistence) TouchAPIToken(ctx context.Context, id int64, at time.Time) error {
	_, err := m.db.ExecContext(ctx, "UPDATE apiTokens SET lastUsedAt = ? WHERE id = ?", at.UTC(), id)
	return err
}
