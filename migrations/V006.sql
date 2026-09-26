-- Extends the one-time state used for cloud login so the same mechanism also
-- protects "link this appliance user to a cloud account" (as opposed to "log
-- in as whichever cloud account this belongs to", which is what a NULL
-- userId here means - see V003's cloudLoginStates). A link state is scoped
-- to the specific local user it was created for, so completing it can never
-- link the wrong user's row.
ALTER TABLE cloudLoginStates
    ADD COLUMN userId BIGINT UNSIGNED NULL,
    ADD CONSTRAINT fk_cloudLoginStates_user FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE;
