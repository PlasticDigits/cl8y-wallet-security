FROM postgres:17.6-bookworm@sha256:f3bd19c606e442c3d7bdfa8002e03fe260a1023351e0ea4598032022b68dd6e3 AS tools
ADD --checksum=sha256:cbe24006683f8eb669266162894b9a522a1af52f2665fbc63a4bb032ed26ac10 https://github.com/FiloSottile/age/releases/download/v1.3.2/age-v1.3.2-linux-amd64.tar.gz /tmp/age.tar.gz
RUN mkdir -p /stage/usr/local/bin /stage/usr/lib/x86_64-linux-gnu \
    && tar --extract --gzip --file=/tmp/age.tar.gz --directory=/stage/usr/local/bin --strip-components=1 age/age \
    && cp /usr/lib/postgresql/17/bin/pg_restore /stage/usr/local/bin/pg_restore \
    && ldd /usr/lib/postgresql/17/bin/pg_restore | awk '/=> \// {print $3} /^[[:space:]]*\// {print $1}' | while read -r lib; do cp -L "$lib" "/stage/usr/lib/x86_64-linux-gnu/$(basename "$lib")"; done

# A clean final stage avoids postgres' inherited anonymous PGDATA VOLUME.
FROM debian:bookworm-20251020-slim@sha256:78d2f66e0fec9e5a39fb2c72ea5e052b548df75602b5215ed01a17171529f706
ARG SOURCE_SHA
LABEL org.opencontainers.image.source="https://git.cl8y.com/code/cl8y-wallet-security" \
      org.opencontainers.image.revision=$SOURCE_SHA \
      org.opencontainers.image.version="backup-sealer-age-1.3.2"
COPY --from=tools /stage/ /
RUN mkdir -p /encrypted /app && chown 999:999 /encrypted && chmod 0700 /encrypted
COPY deploy/seal-backup.sh /app/seal-backup.sh
USER 999:999
WORKDIR /app
ENTRYPOINT ["/bin/bash", "/app/seal-backup.sh"]
