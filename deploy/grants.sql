-- No runtime DDL, grant authority or migration history writes.
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM security_api,security_worker,security_backup;
GRANT USAGE ON SCHEMA public TO security_api,security_worker,security_backup;
GRANT SELECT ON _sqlx_migrations TO security_api,security_worker;
-- API owns profile authentication and proposals. Worker may never mint sessions/proofs/assignments.
GRANT SELECT,INSERT ON profiles,wallets TO security_api;
GRANT SELECT,INSERT,DELETE ON sessions TO security_api;
GRANT SELECT,INSERT,UPDATE ON challenges,assignments,contacts,contact_verifications TO security_api;
GRANT SELECT,INSERT ON security_events,notification_outbox TO security_api;
GRANT SELECT ON worker_heartbeats,chain_checkpoints TO security_api;
-- Notification and finalized ingestion. Retention can DELETE expired authentication rows only.
GRANT SELECT ON profiles,wallets,assignments TO security_worker;
GRANT DELETE ON sessions,challenges TO security_worker;
GRANT SELECT,INSERT,UPDATE,DELETE ON contact_verifications TO security_worker;
GRANT SELECT,UPDATE ON contacts TO security_worker;
GRANT SELECT,INSERT ON security_events,chain_receipts TO security_worker;
GRANT SELECT,INSERT,UPDATE ON notification_outbox,chain_checkpoints,worker_heartbeats,telegram_checkpoints TO security_worker;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO security_backup;
GRANT SELECT(expires_at) ON sessions TO security_worker;
GRANT SELECT(created_at) ON challenges TO security_worker;
