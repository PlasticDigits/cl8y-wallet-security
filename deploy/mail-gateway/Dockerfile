FROM rust:1.91.1-bookworm@sha256:c1e5f19e773b7878c3f7a805dd00a495e747acbdc76fb2337a4ebf0418896b33 AS build
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked --offline
FROM postgres:17.6-bookworm@sha256:f3bd19c606e442c3d7bdfa8002e03fe260a1023351e0ea4598032022b68dd6e3
ARG SOURCE_SHA
LABEL org.opencontainers.image.source="https://git.cl8y.com/code/cl8y-wallet-security" org.opencontainers.image.revision=$SOURCE_SHA
COPY --from=build /build/target/release/wallet-security-mail-gateway /app/mail-gateway
COPY preflight.sh /app/preflight.sh
USER 10001:10001
ENTRYPOINT ["/app/mail-gateway"]
