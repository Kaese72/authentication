-- Permissions embedded into a user's use token as the "hp" claim: an admin
-- flag directly on the user, which grants everything, and - for everyone
-- else - per-resource view/modify grants in their own table.
--
-- "resource" holds one of authentication/usertoken's short resource codes -
-- see usertoken.Resource* / usertoken.KnownResources, which this enum must be
-- kept in sync with: adding a new resource code needs a migration here too
-- (ALTER TABLE userPermissions MODIFY COLUMN resource ENUM(...)). A user with
-- no row for a resource has no access to it. Modify implies view at the
-- application layer, so a row with modifyAccess and not viewAccess is still
-- valid and equivalent to having both.
ALTER TABLE users
    ADD COLUMN isAdmin BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE IF NOT EXISTS userPermissions (
    userId BIGINT UNSIGNED NOT NULL,
    resource ENUM('ds', 'ar', 'us', 'cc') NOT NULL,
    viewAccess BOOLEAN NOT NULL DEFAULT FALSE,
    modifyAccess BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (userId, resource),
    CONSTRAINT fk_userPermissions_user FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE
);
