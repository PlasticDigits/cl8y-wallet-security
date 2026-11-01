# Temporary operator-only ciphertext transport

This separate, short-lived helper reads one completed encrypted age file from
an observed owned volume mounted read-only. It never receives raw dumps, DB,
contact, private age, S3 or operator credentials. The sole capability is a
random 32-byte read token supplied through a protected runtime ENV entry and an
operator HTTP Authorization header. It never accepts credentials in argv,
query strings or files, and never logs requests or headers. Coolify may persist
its own protected runtime environment; do not claim the entire platform writes
no credential files.

The binary hard-binds only `10.8.0.1:18188` and permits cipher reads only from
`10.8.0.2`, over the existing WireGuard path. Host networking is restricted to
this reviewed transport role; it does not change the no-network sealer or
internal-only worker/gateway rules. There is no wildcard/public listener,
Traefik route, Docker socket, privilege/capability, writable data mount or
forwarded-header trust. If the private interface/port is unavailable it fails
closed, without taking over another listener or falling back to public bind.

A fixed filename pattern, 270 MiB ceiling, age header, SHA256, regular-file /
O_NOFOLLOW checks and inode/mtime/size fingerprint bind the data. Startup hashing also enforces the declared byte
count and a 30-second deadline; the monotonic lifetime starts before validation. The operator
must first obtain the sealer's completed-pair pause acknowledgement, keep it
fenced while fetching, verify full ciphertext SHA256 before upload, and resume
in cleanup. This is a transport for ciphertext, not a file-browser or archive
creator. At most two concurrent sessions, 8 KiB headers, five-second header deadline,
120-second transfer deadline, and a maximum ten-minute wall/monotonic lifetime
bound the helper. Expiry closes the listener; restart is disabled.

The operator controller must validate actual private bind/peer, image/source,
read-only single-volume scope and zero forbidden credentials before fetching;
confirm deletion after use and recover stale helper metadata on retry. Scoped
read-token TTL is an additional fail-closed boundary if cleanup is interrupted.
No export/upload is authorized merely by source tests: actual volume binding,
controller review and runtime private-interface proof remain required.
