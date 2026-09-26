-- Without this, every user who existed before permissions were introduced
-- would default to isAdmin = FALSE (no access at all) on their next login.
-- Grant them all admin instead, so nobody's access silently changes as part
-- of this rollout - an admin can then dial individual users back down.
--
-- Restricted to users with a local password: cloud users (passwordHash NULL,
-- see V003) are re-verified against the cloud on every login and may not be
-- the appliance owner, so they should not be silently made admin here - an
-- existing admin can grant one permissions explicitly if warranted.
UPDATE users SET isAdmin = TRUE WHERE passwordHash IS NOT NULL;
