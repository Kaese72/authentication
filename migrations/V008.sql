-- API tokens: long-lived, opaque bearer tokens a user provisions for
-- themselves (see usertoken.APITokenPrefix for the format). Unlike use
-- tokens they are not verified locally by the receiving service but looked
-- up here (POST .../internal/api-tokens/introspect) on use, so revoking one,
-- or changing its owner's permissions, takes effect within the consuming
-- service's short introspection cache.
--
-- Only the SHA-256 hash of a token's secret is stored; publicId is the
-- non-secret part of the token used to find its row. permissions is the
-- token's own scope, in the same JSON shape as the use token hp claim
-- (usertoken.Permissions); what a token actually grants is always that scope
-- intersected with its owner's current permissions. expiresAt NULL means the
-- token never expires.
CREATE TABLE IF NOT EXISTS apiTokens (
    id SERIAL PRIMARY KEY,
    userId BIGINT UNSIGNED NOT NULL,
    publicId CHAR(16) NOT NULL,
    secretHash BINARY(32) NOT NULL,
    name VARCHAR(100) NOT NULL,
    permissions JSON NOT NULL,
    expiresAt TIMESTAMP NULL DEFAULT NULL,
    lastUsedAt TIMESTAMP NULL DEFAULT NULL,
    createdAt TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT unique_apiTokens_publicId UNIQUE (publicId),
    CONSTRAINT fk_apiTokens_user FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE
);
