ALTER TABLE contacts ADD COLUMN activation_at timestamptz;
ALTER TABLE contacts ADD COLUMN consent_at timestamptz;
ALTER TABLE notification_outbox ADD COLUMN encrypted_payload bytea;
CREATE INDEX challenge_global_rate ON challenges(created_at);
CREATE TABLE telegram_checkpoints (bot_name text PRIMARY KEY, next_update_id bigint NOT NULL DEFAULT 0);
ALTER TABLE contact_verifications ADD COLUMN purpose text NOT NULL DEFAULT 'email';
