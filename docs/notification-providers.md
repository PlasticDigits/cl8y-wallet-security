# Notification provider continuation — issue 3

Owner: BB thread `thr_ywz2dcyd3p`, lead `thr_wur9hgwhec`, coordinator
`thr_4rw76j9ker`. This source is a separate proposed increment from live source
`e44569e45b15dbee4b0347dff742f92bd85bedb2`; provider activation is not implied.
Keep issue 3 open until independently reviewed runtime and owned delivery evidence
exist. No live deployment, DB credentials or runtime hostname hook are changed.

## Authorized inventory, 2026-10-31

- `bao-exec --list` has no portal Resend/SMTP/Telegram credential. This is only
  workstation inventory, not evidence that enrollment is impossible.
- Names-only `cl8y-pm/docs/OPENBAO.md` identifies Mailu, group `mail`, and Coolify
  service env names `API`, `API_TOKEN`, `WEB_API`. The reviewed backup/recovery
  runbooks describe fixed backup transport/custody; they do not enroll senders.
- Authorized `COOLIFY_WIRE_TOKEN,COOLIFY_URL` injection through the existing VPN
  works. Mailu service `kzcsybgqrftglacdf3j8bfk1` has the API enabled and a token.
  That token is consumed only in process memory for enrollment; never give it to
  the portal. `https://mail.cl8y.com/api/v1/domain` and the exact managed domain
  lookup returned HTTP 200. Swagger/UI routes returned 404, which did not mean
  the enrollment API was unavailable.
- Routine `bao-admin` certificate access works. Names-only AppRole listing had
  no portal workload. Existing Mailu worker group is the exact KV object
  `secret/data/cl8y/groups/mail`, not the nonexistent `groups/mail/*` tree.
  The legacy group's values are not needed for portal enrollment and were not
  copied. Existing shared workstation and worker identities remain separate.
- Scoped portal SMTP custody is `secret/data/groups/cl8y-wallet-security/mailu_smtp`.
  No workload receives admin authentication. A future workload reader must have
  read access to this exact object only, or the deployment owner may inject its
  scoped token directly into protected runtime-only Coolify env in memory.
- No portal bot or bot-management enrollment capability was found in the broker,
  available tools, OpenBao group/AppRole names, or the relevant workstation,
  workload, forge and portal setup documentation. Existing ops/intake/CI bots
  have other consumers and must not be borrowed or polled. The precise missing
  capability is an authorized independent portal bot token, or an authorized
  Telegram BotFather/managed-bot creation session. This remains agent-owned;
  no operator task or real-recipient message is created.

## Disabled sender preparation

`ops/notifications/enroll-mailu.py` consumes only the two authorized Coolify operator names
and routine local OpenBao administration. It creates a dedicated service mailbox
only if absent, with disabled login/sending, no administration, spoofing,
IMAP/POP, forwarding or auto-replies, and a 10 MiB quota. Its random account
password is discarded, never used by the portal. The separate mailbox token is
initially restricted to a non-routable TEST-NET address. Its token and enrollment
identity go to the exact portal KV object with CAS=0 and memory-only readback.
Existing unrelated or unowned accounts are never adopted or rotated. Rerunning
only verifies matching disabled scope; it does not enable or change anything.
No local secret file, dotenv, command-line credential or mail send is produced.

The enrollment script's receipt proves disabled preparation only. It cannot
prove delivery, SMTP authentication, an outbound source IP, or readiness.

## Narrow SMTP/gateway contract

`EMAIL_PROVIDER=smtp` selects a fixed service sender and TLS identity; there is no
request-controlled host, port, From or envelope sender. The worker connects to
`mail.cl8y.com:1587` on a dedicated internal Docker network. The credential-free
proposed `mailu-egress` binary relays only to the reviewed fixed Mailu IP
`167.233.253.175:587`, with four concurrent connections, five-second connect and
25-second total connection bounds. No proxy method, URL, destination argument,
published port, request parsing or logging exists. Required STARTTLS and public
CA/hostname verification happen end-to-end in the worker before AUTH or data.
The worker's whole send is bounded at 15 seconds. SMTP protocol errors,
destinations, credentials and payloads never become logs.

The deployment owner owns the separate gateway/opt-in overlay integration.
Credential-free candidate source and overlay are in the private program handoff
`/tmp/cw20-security-program/mailu-gateway-candidate`; neither is included or
enabled by this provider source PR.
The worker remains on private networks, and the relay has its own outbound
network with no unrelated apps. API receives only `EMAIL_PROVIDER` and the
nonsecret `MAILU_EMAIL_ENABLED` readiness flag. Only worker receives
`MAILU_SMTP_TOKEN`. No new worker is created. Integrating the overlay requires
independent review of the exact source/image, generated network boundaries and
the deployment owner's existing runtime PostgreSQL hostname hook. Never replace
that hook or put worker onto the shared proxy network.

Before enablement the deployment owner must prove the actual source IP observed
at Mailu using non-authenticated TCP/STARTTLS traffic. Public ingress DNS is not
that proof, especially if VPN routing changes the source. After review, replace
only this owned token's TEST-NET AuthorizedIP with the verified exact source,
enable only this mailbox, inject only the scoped token into worker runtime, and
verify permitted fixed SMTP and denied unrelated egress from the actual worker
network. Keep `MAILU_EMAIL_ENABLED=false` until an explicit owned/sandbox
delivery check and fresh independent review pass. Use
`NOTIFICATION_SANDBOX_DESTINATIONS` for those checks, configured only on worker;
never send to real recipients as an operator test. The live deployment is not
modified by preparing this source or mailbox.

Migration 6 persists the first attempted transport, including classification of
attempted legacy rows as their original Resend/Telegram mode. Blocked rows that
have never attempted a configured send remain eligible for initial transport
selection. SMTP/Telegram expired leases fail with `delivery_uncertain`; only
Resend is reclaimable within its deduplication window. Changing a provider never
replays a pinned item on the replacement. Do not roll back to a worker unaware
of migration 6 after SMTP is enabled; preserve and inspect uncertain outcomes.

Primary contracts: [Mailu API](https://mailu.io/2024.06/api.html),
[Mailu user API](https://github.com/Mailu/Mailu/blob/2024.06/core/admin/mailu/api/v1/user.py),
[Mailu scoped tokens](https://github.com/Mailu/Mailu/blob/2024.06/core/admin/mailu/api/v1/token.py),
[required STARTTLS](https://docs.rs/lettre/0.11.19/lettre/transport/smtp/struct.AsyncSmtpTransport.html),
[Telegram creation and managed bots](https://core.telegram.org/bots/features#managed-bots).
Telegram managed bot creation still requires an authorized manager and the
owner's creation confirmation; an unrelated bot token is not enrollment authority.
