# Wallet security frontend

Lightweight Vite + strict TypeScript, with no runtime packages. All service requests use same-origin `/api/v1`; production serves `dist/` alongside the Rust API. No RPC, contract address, token decimals, transaction ABI, private key or network fallback is embedded.

## Build and focused verification

Use Node >=22.12 (Node 24 used for verification) and npm:

```sh
cd frontend
npm ci
npm run build
npm test
```

`build` type-checks before producing `dist/`. The committed lockfile pins tooling. `npm test` uses one Chromium worker and starts a local Vite server on 127.0.0.1:4177. Set `CHROME_PATH` to an installed Chromium executable if `/opt/google/chrome/chrome` is unavailable. It does not download a browser. Browser traces, videos and screenshots are disabled by default; only synthetic fixture data is used. `PORTAL_SCREENSHOT=/tmp/portal-synthetic.png npm test` can capture the synthetic unsigned mobile page for visual inspection.

Focused rendered checks cover login, independent wallet enrollment, candidate/owner separation, consent, cancellation, refresh persistence, active roles during removal, expiry/account invalidation, contact delivery states, safe Telegram URLs, contact activation delay, escaped service text, keyboard focus, a 375px layout, and WCAG A/AA rules using axe. A decimal formatting check preserves maximum u128 values without converting token amounts to floating point. These are API/provider doubles, not evidence of live extension signing, backend cryptographic verification, provider delivery or deployment.

## Actual wallet interfaces and support limits

Official references checked October 31, 2026:

- [Keplr enable](https://docs.keplr.app/api/guide/enable-connection), [getKey](https://docs.keplr.app/api/guide/get-key), and [signArbitrary](https://docs.keplr.app/api/guide/sign-arbitrary): request wallet permission, read the selected chain account, and sign the exact challenge string as ADR-036.
- [Official Station extension injection](https://github.com/stationmoney/station-extension/blob/main/scripts/inpage.js) exposes `window.station`; [its Keplr injection](https://github.com/stationmoney/station-extension/blob/main/scripts/keplr.js) uses `station.keplr`. The official [`@terra-money/station-connector` 1.1.4](https://www.npmjs.com/package/@terra-money/station-connector) source was inspected: `KeplrConnector.signArbitrary(chainID, signer, data)` calls Station ADR-036 signing and converts its public key to Amino format. Station's top-level `signArbitrary(bytes, chainID)` has a different signature and is deliberately not called with Keplr arguments.

The UI selects `window.keplr` or `window.station.keplr` explicitly. Both require `enable`, `getKey`, and `signArbitrary`. Only API-configured Terra Classic `columbus-5` is supported; an unsupported/missing chain is rejected. No chain suggestion or arbitrary RPC configuration is attempted. A provider must already support the chain. A wallet permission request or selected address is never treated as authentication: only the API's successful challenge verification establishes it. Injected objects can be supplied by other compatible extensions; their presence does not establish brand authenticity.

Legacy Station without the Keplr bridge, WalletConnect, mobile without an injected compatible provider, and wallets/hardware without compressed secp256k1 ADR-036 signing are unavailable. Real extensions, hardware devices and mobile wallet apps have not been tested in this environment. Connection/signing rejection, missing capability, account changes and expired challenges remain explicit errors. No transaction signing fallback exists.

## Authentication and profile behavior

The immutable login anchor establishes the profile through a one-use server challenge. Added wallets prove independent control within that authenticated profile; they do not become login anchors. Candidate consent requires reconnecting the exact candidate account and signing `assignment:<id>`; an owner signature cannot substitute. The review shows purpose, signer, chain, origin, expiry, exact server message, role and assignment deadline before signing. The API remains responsible for signature verification, nonce/expiry, canonical document, address/purpose/profile binding and authorization. Wallet names, contact destinations, signatures and verification tokens are not logged or persisted in browser storage.

CSRF remains in memory and is restored from `/me`. Cookies are managed only by the API. Failed/expired sessions clear sensitive frontend state. Ambiguous profile writes block further changes until a fresh server snapshot. Refresh and browser restoration invalidate stale proofs/reviews. Account-change events discard prepared proofs; selected account is checked immediately before and after signing, including when an extension does not emit an event.

Assignments are rendered from `/me`, including `proposed_at`, `executable_at`, `accepted_at`, `delay_seconds` and `removal_at`. Profile estimates use `server_time` plus elapsed monotonic browser time; if the server omits it, the device-clock fallback is explicitly labeled. Chain timestamps are unavailable. Countdown completion never activates/removes anything locally. Refresh reloads server state; active roles remain visible throughout scheduled removal. Review distinguishes proposal cancellation from delayed removal and explains that the server's current state controls the result. Replacements are new immutable proposals; existing assignments remain.

## Contacts and readiness

Integration follows the parent API contract:

- `/status.notifications`: `delivery_enabled`, `email_ready`, `telegram_ready`. Readiness is shown per channel; missing status is unavailable.
- `POST /contacts/email {address}`: only explicit `{queued:true,sent:false}` is described as queued, with delivery unconfirmed. 503 remains unavailable and never implies a verification was sent.
- `POST /contacts/email/verify {token}`: refresh authoritative contact status after acceptance.
- `POST /contacts/telegram {}`: render the API's configured `pairing_url` only for HTTPS `t.me`, a bot-name path, no credentials/port, and a `start` parameter. The user starts the bot and pastes its confirmation code into `POST /contacts/telegram/confirm {token}`.
- `/me.contacts`: show kind/status only, `activation_at` for pending contact additions, and `removal_at` for delayed removal. No email address or chat ID is listed. Previous verified contacts stay effective during the addition delay. Verified removals are delayed; unverified contacts may be removed immediately.
- `POST /contacts/:id/remove {}`: review before scheduling; refreshed state controls the displayed deadline. A scheduled warning is not proof of delivery.

Email inputs and confirmation codes are cleared immediately on submission. Pairing links remain only in memory and clear on profile/session change or completed confirmation. No recipient or real delivery tests were performed.

## Explicitly gated scope

The API currently exposes profile identity/assignments/contacts but no authoritative token portfolio/settings/recovery read interface. On-chain coverage, balances, migration status, effective/pending rate limits, delayed opt-out/relaxation, lock/unlock/cancel/relock, and recovery/disputes are explicitly unavailable. The UI never infers safety for existing unmigrated tokens and never shows proposed defaults as effective. Even a future `chain.status:ready` cannot enable these actions without a reviewed versioned ABI, verified deployment identities and authoritative reads. Thus there is no invented transaction preview, token amount or live-protection claim.

Profile role/contact proofs do not confer token authority. Trusted CL8Y governance is an explicit assumption; containment, unpause, recovery authorization, execution and key rotation are described as separate powers. Social accounts or contact possession cannot establish asset ownership. Full issue #2 acceptance remains dependent on contract/deployment integration and live wallet/delivery verification; source/build success alone is not deployment evidence.
