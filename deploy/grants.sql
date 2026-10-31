-- Migrator owns DDL; runtimes cannot create schema objects or change migration history.
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM security_api,security_worker,security_backup;
GRANT USAGE ON SCHEMA public TO security_api,security_worker,security_backup;
GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA public TO security_api,security_worker;
REVOKE ALL ON _sqlx_migrations FROM security_api,security_worker;
GRANT SELECT ON _sqlx_migrations TO security_api,security_worker;
REVOKE INSERT,UPDATE,DELETE ON worker_heartbeats FROM security_api;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO security_backup;
GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA public TO security_api,security_worker;
