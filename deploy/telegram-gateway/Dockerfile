FROM rust:1.91.1-bookworm@sha256:c1e5f19e773b7878c3f7a805dd00a495e747acbdc76fb2337a4ebf0418896b33 AS build
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src/main.rs ./src/main.rs
RUN cargo build --release --locked --offline
FROM debian:bookworm-slim@sha256:99c0b25c46d0214d5a2091092e7908907dcaecd6a962cde0ac700acee222b6f3
ARG SOURCE_SHA
LABEL org.opencontainers.image.source="https://git.cl8y.com/code/cl8y-wallet-security" org.opencontainers.image.revision=$SOURCE_SHA
COPY --from=build /build/target/release/wallet-security-telegram-gateway /app/telegram-gateway
USER 10001:10001
ENTRYPOINT ["/app/telegram-gateway"]
