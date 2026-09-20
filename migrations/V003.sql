-- Cloud users: people who log in with their Humi Cloud account instead of a
-- local password. They get a local row (so every existing endpoint that deals
-- in local user ids keeps working) linked to their cloud user id, and no
-- local password - passwordHash is NULL, which can never match a login.
ALTER TABLE users
    MODIFY COLUMN passwordHash VARCHAR(255) NULL,
    ADD COLUMN cloudUserId BIGINT UNSIGNED NULL,
    ADD CONSTRAINT unique_cloud_user_id UNIQUE (cloudUserId);

-- One-time "state" values for in-flight cloud logins: issued when the login
-- page sends the browser to the cloud, consumed when it comes back with a
-- login code. Only proves this appliance started the login; the browser
-- additionally holds its own copy to guard against login CSRF.
CREATE TABLE IF NOT EXISTS cloudLoginStates (
    state CHAR(64) NOT NULL PRIMARY KEY,
    expiresAt TIMESTAMP NOT NULL,
    createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
