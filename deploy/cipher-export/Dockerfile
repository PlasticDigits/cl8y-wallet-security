FROM rust:1.91.1-bookworm@sha256:c1e5f19e773b7878c3f7a805dd00a495e747acbdc76fb2337a4ebf0418896b33 AS build
WORKDIR /build
COPY deploy/cipher-export/Cargo.toml deploy/cipher-export/Cargo.lock ./
COPY deploy/cipher-export/src ./src
RUN cargo build --locked --release -j 2
FROM debian:bookworm-20251020-slim@sha256:78d2f66e0fec9e5a39fb2c72ea5e052b548df75602b5215ed01a17171529f706
ARG SOURCE_SHA
LABEL org.opencontainers.image.source="https://git.cl8y.com/code/cl8y-wallet-security" org.opencontainers.image.revision=$SOURCE_SHA
WORKDIR /app
COPY --from=build /build/target/release/wallet-security-cipher-export /app/cipher-export
USER 999:999
ENTRYPOINT ["/app/cipher-export"]
