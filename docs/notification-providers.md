# Notification provider continuation — issue 3

Owner: BB thread `thr_ywz2dcyd3p`, lead `thr_wur9hgwhec`, coordinator
`thr_4rw76j9ker`. The initial provider increment was separate from then-live source
`e44569e45b15dbee4b0347dff742f92bd85bedb2`; later actual activation is recorded
below. The coordinator owns the main release, DB credentials and runtime hostname
hook. Issue 3 stays open for acceptance still explicitly listed as pending.

Continuation, 2026-11-01: the coordinator released source
`4fbe03977337925f6185b393a8aa39437095b097` with migration 6 and independently
verified worker isolation. One reviewed owned API/IMAP trial then actually
received three distinct notices: double opt-in confirmation, an assignment timer
with its exact deadline, and the old verified channel's removal warning. Code
replay was rejected and the old channel remained effective through its delay.
The exact receipt is
`deploy/receipts/2026-11-01-owned-notification-delivery-c8f69f7.json`.
Both owned accounts were enabled for that trial. The coordinator then separately
accepted a fresh schema6 off-host restore preserving the three actual SMTP
sent/first-attempt rows and full timer/outbox/contact metadata. The owned profile
was present with zero active source sessions, confirming no further login/logout
was needed. After that acceptance, the reviewed receiver-retirement helper
disabled only the smoke receiver, revoked its exact token and removed its
credential from current custody through CAS/readback. The normal sender remained
enabled with the verified gateway restriction in a subsequent read-only check.
Actual cleanup and sender receipts are
`deploy/receipts/2026-11-01-smoke-retirement-e4b9a43.json` and
`deploy/receipts/2026-11-01-sender-after-smoke-retirement.json`.
No portal, outbox, profile, mailbox contents or private recovery checkpoint was
deleted. The coordinator's reviewed production-mode job then removed the owned
allowlist without another provider test/send. Actual public health and worker
source remained `4fbe039`, migration 6, with email/delivery ready and pending0 /
failed0. The final scoped email record is
`deploy/receipts/2026-11-01-email-production-final.json`; its off-host proof links
the backup owner's immutable schema6 artifact. Telegram acceptance is still
pending and is not inferred from owned email success.

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

The deployment coordinator owns the main worker/opt-in overlay integration.
The separate credential-free gateway is maintained in `deploy/mail-gateway/`;
its source44 retained container was activated through reviewed ops source60a9544
on 2026-11-01. Its exact runtime, cleanup and receiver-side source-IP evidence
are recorded in `deploy/receipts/2026-11-01-gateway-activation-60a9544.json`.
Gateway activation does not attach the portal worker or enable a provider.
The worker remains on private networks, and the relay has its own outbound
network with no unrelated apps. API receives only `EMAIL_PROVIDER` and the
nonsecret `MAILU_EMAIL_ENABLED` readiness flag. Only worker receives
`MAILU_SMTP_TOKEN` and an explicit `MAILU_DELIVERY_ENABLED=true` switch.
The worker fails closed without that exact enable value, even if a token was
injected. `MAILU_EMAIL_ENABLED` controls API readiness only; it is not the worker
kill switch. For credential-bearing staged checks keep worker delivery disabled,
or explicitly enable it with an owned-only `NOTIFICATION_SANDBOX_DESTINATIONS`
allowlist. No new worker is created. Integrating the overlay requires
independent review of the exact source/image, generated network boundaries and
the deployment owner's existing runtime PostgreSQL hostname hook. Never replace
that hook or put worker onto the shared proxy network.

The actual source IP observed at Mailu was independently proven using
non-authenticated STARTTLS traffic: the exact owned-window submission-login
record identifies `168.119.120.255` as `rip`, with local port 587, TLS and no
authentication attempts. Only this owned token's TEST-NET restriction was
replaced with `168.119.120.255/32`; the sender stayed disabled at that stage. Its custody
state became `ip-restricted-disabled`, with the same token preserved and CAS
readback verified in `deploy/receipts/2026-11-01-mailu-ip-restriction-3f4700b.json`.
The old TEST-NET inspection helper intentionally rejects later states;
`restrict-mailu-ip.py` verifies only the IP-restricted disabled stage. The reviewed
`enable-owned-smoke.py` subsequently enabled only the two owned accounts and
advanced their custody to `enabled-owned-smoke`, preserving their credentials
and IP restrictions. The sender token was injected only into worker runtime,
initially with delivery disabled. The coordinator must
verify permitted fixed SMTP and denied unrelated egress from the actual worker
network. Keep both delivery/readiness switches false outside a separately gated
owned trial. The API flag must temporarily be true to exercise its actual opt-in
route; during that bounded window the worker must enforce the exact
`wallet-security-smoke@cl8y.com` sandbox allowlist. The coordinator decides final
explicit opt-in enablement or restores false flags after independent actual
delivery review. No direct SQL/outbox synthesis or real-recipient operator test
is used. Preparing this source and disabled accounts does not release the main
portal application.

The separate fixed smoke receiver was initially created disabled, non-admin and limited
to 10 MiB, with no forwarding/spoofing/POP and with IMAP enabled as its intended
use. Its discarded password and separate token custody never enter the portal.
The token was restricted to the workstation interface `/32` provisionally;
the actual bounded hostname-verified IMAP login subsequently accepted that
restriction. This is distinct from a receiver-log NAT observation. Mailu
account tokens are not protocol-specific.
The actual preparation receipt is
`deploy/receipts/2026-11-01-smoke-mailbox-0965c07.json`. The proposed bounded
API/IMAP trial keeps only its unfunded generated wallet keys and initial mailbox
UID boundary in exact privateKV `mailu_smoke_trial`, so interrupted acceptance
can recover the same owned profile without another verification request.

Migration 6 persists the first attempted transport and attempt timestamp, including
classification of attempted legacy rows as their original Resend/Telegram mode
with conservative created-at timestamps. Blocked rows that
have never attempted a configured send remain eligible for initial transport
selection. SMTP/Telegram expired leases fail with `delivery_uncertain`; only
Resend is reclaimable within 23 hours of its persisted first attempt. This bound
also applies to pending/blocked retries after downtime or provider switching;
aged attempted rows become terminal uncertainty. Known pre-send sandbox/config
blocks clear initial provisional transport/timestamp selection, consume no
attempt, and remain eligible for a later first send. Changing a provider never
replays a pinned item on the replacement. Do not roll back to a worker unaware
of migration 6 after SMTP is enabled; preserve and inspect uncertain outcomes.

Primary contracts: [Mailu API](https://mailu.io/2024.06/api.html),
[Mailu user API](https://github.com/Mailu/Mailu/blob/2024.06/core/admin/mailu/api/v1/user.py),
[Mailu scoped tokens](https://github.com/Mailu/Mailu/blob/2024.06/core/admin/mailu/api/v1/token.py),
[required STARTTLS](https://docs.rs/lettre/0.11.19/lettre/transport/smtp/struct.AsyncSmtpTransport.html),
[Telegram creation and managed bots](https://core.telegram.org/bots/features#managed-bots).
Telegram managed bot creation still requires an authorized manager and the
owner's creation confirmation; an unrelated bot token is not enrollment authority.
