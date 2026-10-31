# Immutable upstream manifests; Cargo.lock and package-lock.json pin dependencies.
FROM node:24.11.1-bookworm-slim@sha256:48abc13a19400ca3985071e287bd405a1d99306770eb81d61202fb6b65cf0b57 AS web
WORKDIR /build/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM rust:1.91.1-bookworm@sha256:c1e5f19e773b7878c3f7a805dd00a495e747acbdc76fb2337a4ebf0418896b33 AS api
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY api/ api/
RUN cargo build --locked --release -p wallet-security-api -j 2

# Includes libssl, CA roots and version-matched PostgreSQL backup/client tools.
FROM postgres:17.6-bookworm@sha256:f3bd19c606e442c3d7bdfa8002e03fe260a1023351e0ea4598032022b68dd6e3 AS runtime
ARG SOURCE_SHA
LABEL org.opencontainers.image.source="https://git.cl8y.com/code/cl8y-wallet-security" \
      org.opencontainers.image.revision=$SOURCE_SHA
WORKDIR /app
RUN mkdir /backups && chown postgres:postgres /backups && chmod 0700 /backups
COPY --from=api /build/target/release/wallet-security-api /app/wallet-security-api
COPY --from=web /build/frontend/dist /app/frontend/dist
COPY deploy/ /app/deploy/
ENV WEB_ROOT=/app/frontend/dist
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=20s --timeout=5s --start-period=30s --retries=3 CMD ["/bin/bash", "/app/deploy/healthcheck.sh"]
ENTRYPOINT ["/bin/bash", "/app/deploy/entrypoint.sh"]
