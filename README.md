# CL8Y Wallet Security

A public noncustodial wallet-security portal built with Rust, TypeScript and PostgreSQL. The API holds no wallet keys and never signs or broadcasts privileged token actions. Wallet profiles and notification roles confer no blockchain authority.

Implemented:

- Terra Classic ADR-036 wallet authentication with one-use, expiring, origin/chain/purpose-bound challenges; independently proven multiple wallets; Secure HttpOnly sessions, origin/CSRF protection and bounded admission.
- Delayed dual-consent profile assignments, immutable candidate/role/nonce, old-delay snapshots, replacement, cancellation and delayed active removal.
- Encrypted email double opt-in and one-use Telegram pairing/confirmation; prior-contact warnings, delayed channel changes and private retention.
- Transactional warning outbox, semantic/receipt deduplication, per-item leases, bounded retry and visible delivery uncertainty/failure/backlog. No per-transfer notices.
- Versioned contract queries and finalized receipt ingestion with reviewed chain/contract/code-ID allowlists, pinned read heights and durable replay/divergence handling. Controller timer fanout uses bounded durable pages.
- Responsive accessible frontend, exact signature previews, PostgreSQL-backed timers and explicit unsupported/unmigrated/unavailable chain state.
- Nonroot deployment, dedicated private PostgreSQL, separate migration/runtime roles, backup and bounded scratch restore, health/source/migration/worker evidence.

Deployment readiness is recorded separately in [deployment documentation](docs/deployment.md). A reachable portal is not proof that token protections are deployed or notifications delivered. Live contract controls require the exact independently reviewed ABI and verified deployment identities. Provider credentials gate their channels; operator tests use owned/sandbox recipients only. Until configured, those functions explicitly report unavailable. Existing native coins/unmigrated/unlisted contracts are uncovered.

Read [API contract](docs/api-contract.md), [security/privacy and account limitations](docs/security-and-privacy.md), [chain integration](docs/chain-integration.md) and [frontend support/validation](frontend/README.md).

Development uses stable Rust with `Cargo.lock`, Node with `frontend/package-lock.json`, and disposable PostgreSQL17. `cargo check --locked` checks the backend; `cargo test --locked` runs focused checks. Set `TEST_DATABASE_URL` to an owned disposable PostgreSQL database to include actual persistence, concurrency, timer, outbox and local-chain-fixture tests; absent it, the integration case explicitly skips. Never point tests at production. `npm ci --ignore-scripts` and `npm run build` in `frontend/` check the UI; `npm test` runs its focused owned API/provider doubles. These checks do not send real notifications or chain transactions.

Production credentials are supplied through authorized workload/Coolify runtime mechanisms. No credentials, contact data, raw evidence, private keys or operational secrets belong in this public repository, command arguments, logs or local dotenv files. The profile anchor is immutable; loss of it has no social/contact override. See the explicit account limitation before relying on a portal profile.
