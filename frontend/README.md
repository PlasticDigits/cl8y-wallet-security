# Wallet security frontend

Vite + strict TypeScript, with lazily loaded pinned CosmJS signing packages. All service requests use same-origin `/api/v1`; production serves `dist/` alongside the Rust API. No deployed RPC endpoint, contract address, token decimals, private key or network fallback is embedded; deployment identities come only from verified operator configuration. The reviewed security ABI v1 source is pinned explicitly.

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

Assignments are rendered from `/me`, including `proposed_at`, `executable_at`, `accepted_at`, `delay_seconds` and `removal_at`. Profile estimates use `server_time` plus elapsed monotonic browser time; if the server omits it, the device-clock fallback is explicitly labeled. These profile timers are separate from finalized-chain token timers. Countdown completion never activates/removes anything locally. Refresh reloads server state; active roles remain visible throughout scheduled removal. Review distinguishes proposal cancellation from delayed removal and explains that the server's current state controls the result. Replacements are new immutable proposals; existing assignments remain.

## Contacts and readiness

Integration follows the parent API contract:

- `/status.notifications`: `delivery_enabled`, `email_ready`, `telegram_ready`. Readiness is shown per channel; missing status is unavailable.
- `POST /contacts/email {address}`: only explicit `{queued:true,sent:false}` is described as queued, with delivery unconfirmed. 503 remains unavailable and never implies a verification was sent.
- `POST /contacts/email/verify {token}`: refresh authoritative contact status after acceptance.
- `POST /contacts/telegram {}`: render the API's configured `pairing_url` only for HTTPS `t.me`, a bot-name path, no credentials/port, and a `start` parameter. The user starts the bot and pastes its confirmation code into `POST /contacts/telegram/confirm {token}`.
- `/me.contacts`: show kind/status only, `activation_at` for pending contact additions, and `removal_at` for delayed removal. No email address or chat ID is listed. Previous verified contacts stay effective during the addition delay. Verified removals are delayed; unverified contacts may be removed immediately.
- `POST /contacts/:id/remove {}`: review before scheduling; refreshed state controls the displayed deadline. A scheduled warning is not proof of delivery.

Email inputs and confirmation codes are cleared immediately on submission. Pairing links remain only in memory and clear on profile/session change or completed confirmation. No recipient or real delivery tests were performed.

## Authoritative chain reads and direct transactions

Contract source/schema pin: [`2d70d43c651ecd4491c0736c89ae2975ee825686`](https://git.cl8y.com/code/cw20-mintable/commit/2d70d43c651ecd4491c0736c89ae2975ee825686), including `WalletResponse.initialized`; [independent token review receipt](https://git.cl8y.com/code/cw20-mintable/issues/7#issuecomment-65389). `src/chain.ts` mirrors the reviewed `src/msg.rs`, `src/security.rs`, `src/recovery.rs` and controller `GuardResponse` v1. Unsupported source pins, unsafe JSON integers, malformed raw responses, unknown token identities, missing HTTPS RPC or unavailable service snapshots gate all chain controls.

`/me.chain` must be `ready` with configured `columbus-5`, exact supported `abi_sha`, `controller`, `contracts:[{address,code_id}]` and operator HTTPS `rpc_url`. No deployed identities are supplied in this source. Configuration alone is not evidence of effective wallet protection. Query endpoints require a session; wallet queries also require independently proved profile membership. This authorizes reads only, not transactions.

- `GET /chain/wallet/{token}/{wallet}` returns `{chain_id,contract,controller,chain_time,height,wallet_security,guard,token_info,balance}`. `height` is a decimal string, `chain_time` is finalized-block RFC3339, `guard.blocked` contains exactly the requested wallet. The raw response supplies policy, initialized/lazy basis, buckets, rolling spend, reserved amount, lock, pending payload and exact governance assignment. Amounts remain strings/BigInt with queried token decimals. Rate budget is conditional, not transfer authorization.
- `GET /chain/recovery/{token}/{nonce}` returns `{chain_id,contract,chain_time,height,recovery}`. Read a known nonce; no case list is inferred. Exact source/destination/amount/digest, acceptance/revocation, objection/resolution/veto, authority epoch, cancellation, completion and replacement are shown. No private evidence is collected.

Owner messages are exact snake_case: `set_wallet_policy`, `rebase_protection`, `lock_wallet`, `request_unlock`, `execute_wallet_change {nonce}`, `cancel_wallet_change`. Policy inputs come only from the query. Any weakening delays the whole payload under the old relaxation delay; tightening or lock invalidates pending changes. Execution remains disabled until **queried chain time** reaches the deadline. Countdowns estimate from block time plus monotonic elapsed time and never mutate status. Rebase captures balance at execution; the queried balance is a reference, not a promised amount. `initialized` distinguishes persisted basis from a lazy query.

Recovery controls use `accept_recovery {nonce}`, `revoke_recovery_acceptance {nonce}` and `object_recovery {nonce}`. Exact source/destination account, case flags and authority epoch govern availability. Revocation is permanent for a nonce. Objection cannot cancel, unreserve, change destination or reset the contest. Acceptance binds the immutable case and never executes it. Governance proposal, adjudication/veto, two-role cancellation and recovery-role execution remain outside these owner controls.

[Keplr's official Amino interface](https://docs.keplr.app/api/guide/sign-a-message) is `signAmino(chainId, signer, StdSignDoc, options)`. Official Station connector 1.1.4 `KeplrConnector.signAmino` delegates to `StationOfflineSigner.signAmino`, which checks selected chain/account and calls `window.station.sign` in legacy Amino mode. The adapter uses that bridge, never a mismatched top-level method. Missing `signAmino` blocks preparation. Station/hardware implementations that change the reviewed fee/document or cannot encode the message are rejected. There is no signing fallback.

Pinned CosmJS 0.38.1 simulates `/cosmwasm.wasm.v1.MsgExecuteContract` with **no native funds**, then computes the exact fee from operator `gas_price`. Missing/invalid gas price blocks preparation without inventing a denomination. Explicit `gas_adjustment` is used, otherwise the pinned signing client's verified default **1.4** is disclosed. RPC requests time out after 20 seconds; only reported consensus RPC 0.37/0.38/1.x is supported. See the [official signing client API](https://cosmos.github.io/cosmjs/latest/cosmwasm-stargate/classes/SigningCosmWasmClient.html); installed 0.38.1 source was checked for simulation, fee calculation and Amino conversion. Terra Classic core [v3.6.1 dependencies](https://github.com/classic-terra/core/blob/v3.6.1/go.mod) use CometBFT 0.37; [current source](https://github.com/classic-terra/core/blob/main/go.mod) uses 0.38. Neither establishes any deployed endpoint's version/readiness.

Review shows exact chain/token/code/controller/source pin, signer, old/new state, message, gas and fee in native **base units**; native decimals are not assumed. Before/after wallet signing the adapter checks account, fresh API state/config and direct RPC token code/controller identity. Returned signing-document alterations, including fee changes, are rejected before requesting broadcast. Fees may be charged on execution failure. Only receipt hash/height/code establishes inclusion; nonzero code is failure. Ambiguous broadcast is unconfirmed, never automatically retried. Snapshots/reviews are invalidated after submission and must be reloaded.

Nine focused checks cover original profile/contact flows plus authoritative chain rendering, exact large amounts, source/fee gates, old-delay/nonce semantics, case authority/epoch, unsafe integers, actual lazy browser-client RPC failure, simulation-before-signing, explicit fee, wallet fee mutation rejection, state change during signing and failed inclusion. Adapter tests inject an explicit client double; browser `.invalid` RPC requests are intercepted locally. No real chain transaction was sent. The dashboard loads separately from larger CosmJS signing chunks; Vite's lazy-chunk size warning is not a build failure.

Notification status reports actual worker last-seen/source and nonzero pending/failed/fanout/verification-rejection counts, plus oldest pending when available. Persistent text adds no alert stream and never claims recipient delivery.

## Remaining acceptance limits

Without verified configuration, token coverage/settings/recovery reads and transactions remain unavailable. Existing unmigrated/third-party tokens, native coins and BSC remain uncovered; proposed defaults are never effective settings. Real extension/hardware/mobile signing, deployed endpoint/CORS compatibility, fee/tax behavior, deployed ABI identity and recipient delivery have not been verified. Doubles and source/build checks do not establish deployment or live protection.

Profile role/contact proofs do not confer token authority. Trusted CL8Y governance is an explicit assumption; containment, unpause, recovery authorization, execution and key rotation are separate powers. Social accounts or contact possession cannot establish asset ownership. Full issue #2 acceptance remains open pending verified deployment and live wallet/delivery evidence.
