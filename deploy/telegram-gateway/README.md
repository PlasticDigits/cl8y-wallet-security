# Fixed Telegram HTTPS relay

This independent credential-free service connects only to
`149.154.166.110:443`. DNS resolved `api.telegram.org` to that address and
OpenSSL verified its public chain and hostname on 2026-11-01. The worker
continues to verify TLS end to end; the relay never decrypts TLS, parses HTTP,
logs streams, receives credentials or accepts a destination parameter.

Its standard-library relay matches the existing bounded Mailu relay: four
active connections, 5-second connection timeout, 25-second absolute lifetime,
8 KiB buffers and bounded concurrent threads. It runs as UID10001, read-only,
without capabilities, mounts or published ports. Its explicit namespace sysctl
allows this nonroot process to bind443 without adding a capability. It attaches
only its own internal `wallet-security-telegram` network and separate outbound
network. An independently reviewed main-worker overlay may add the internal
network to the worker while retaining its private DB and SMTP networks and
absence of default routes. API and PostgreSQL must never join either network.

This directory does not deploy anything, set bot webhooks, consume updates,
change existing ops alert senders or modify the portal's release hooks. Gateway
provisioning must verify the actual fixed image/source, networks, alias,
nonroot process bounds and hostname-verified HTTPS from the actual worker path.
No operator OpenBao/SSH credential enters the runtime. Use the existing pinned
build and runtime bases; Cargo has no third-party dependencies and builds offline.

Focused test:
`cargo test --manifest-path deploy/telegram-gateway/Cargo.toml --locked --offline`.
