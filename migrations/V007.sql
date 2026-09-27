-- Adds the "aa" (adapter-attendant) resource code, kept in sync with
-- usertoken.ResourceAdapters / usertoken.KnownResources - see V004's comment
-- on this enum.
ALTER TABLE userPermissions
    MODIFY COLUMN resource ENUM('ds', 'ar', 'us', 'cc', 'aa') NOT NULL;
