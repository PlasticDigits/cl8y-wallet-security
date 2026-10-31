import { api } from "./api";
import type { Me } from "./api";
import {
  budget,
  chainConfig,
  fingerprint,
  makeIntent,
  nonce,
  validateRecovery,
  validateWallet,
} from "./chain";
import type {
  Action,
  ChainConfig,
  Policy,
  RecoveryRead,
  WalletRead,
} from "./chain";
import { date, escapeHtml as e, formatUnits, remaining } from "./format";
import type { Connection } from "./wallet";
import { prepareTransaction } from "./transactions";
import type { Prepared, Receipt } from "./transactions";

type Context = {
  me?: Me;
  connection?: Connection;
  busy: boolean;
  stale: boolean;
};
type Hooks = {
  context: () => Context;
  perform: (task: () => Promise<void>) => Promise<void>;
  announce: (message: string, error?: boolean) => void;
  render: () => void;
};
let token = "",
  wallet = "";
let snapshot: WalletRead | undefined;
let caseRead: RecoveryRead | undefined;
let prepared: Prepared | undefined;
let receipt: Receipt | undefined;
let generation = 0;
let sample = performance.now();
let recoverySample = performance.now();
export function resetChain() {
  generation++;
  prepared?.dispose();
  prepared = undefined;
  snapshot = undefined;
  caseRead = undefined;
  receipt = undefined;
}
export function chainAvailable(me?: Me) {
  try {
    chainConfig(me?.chain);
    return true;
  } catch {
    return false;
  }
}
function config(context: Context) {
  if (context.stale)
    throw new Error(
      "Refresh the service configuration before using chain controls.",
    );
  return chainConfig(context.me?.chain);
}
function attrs(context: Context, enabled = true) {
  return context.busy || context.stale || !enabled ? "disabled" : "";
}
function btn(context: Context, text: string, action: string, enabled = true) {
  return `<button type="button" data-chain-action="${action}" ${attrs(context, enabled)}>${text}</button>`;
}
function addr(value: string) {
  return `<span class="address">${e(value)}</span>`;
}
function json(value: unknown) {
  return `<pre>${e(JSON.stringify(value, null, 2))}</pre>`;
}
function unix(value: number) {
  return new Date(value * 1000).toISOString();
}
function timer(seconds: number, chainTime: string, sampled: number) {
  const value = unix(seconds);
  return `<time datetime="${e(value)}">${date(value)}</time><span class="countdown" data-chain-deadline="${e(value)}" data-chain-sample="${sampled}" data-chain-time="${e(chainTime)}">${e(remaining(value, Date.parse(chainTime) + performance.now() - sampled).replace("server status", "chain status"))}</span>`;
}
function policyView(policy: Policy) {
  return `<dl><dt>Rate protection</dt><dd>${policy.enabled ? "Enabled" : "Opted out"}</dd><dt>Rolling limit</dt><dd>${policy.limit_bps} basis points (${formatUnits(String(policy.limit_bps), 2)}%)</dd><dt>Relaxation delay</dt><dd>${policy.relaxation_delay}s</dd><dt>Unlock delay</dt><dd>${policy.unlock_delay}s</dd></dl>`;
}
function walletView(context: Context, w: WalletRead) {
  const s = w.wallet_security,
    p = s.state.policy;
  const signing =
    context.connection?.address === s.wallet && !!context.me?.chain.gas_price;
  const amount = (value: string) =>
    `${e(formatUnits(value, w.token_info.decimals))} ${e(w.token_info.symbol)}`;
  const activeLimit = p.enabled && !s.assignment.exempt;
  return `<article class="chain-wallet"><div class="row"><h3>${e(w.token_info.name)} (${e(w.token_info.symbol)})</h3><span class="badge ${w.guard.enrolled ? "good" : "warn"}">${w.guard.enrolled ? "Controller enrolled" : "Unenrolled — ordinary actions blocked"}</span></div>
    <p>Wallet ${addr(s.wallet)}</p><dl><dt>Balance</dt><dd>${amount(w.balance.balance)}</dd><dt>Protection basis</dt><dd>${amount(s.state.protected_balance)} · ${s.initialized === true ? "Persisted" : s.initialized === false ? "Lazy current balance; not yet persisted" : "Initialization status unavailable"}</dd><dt>Rolling debit history</dt><dd>${amount(s.rolling_spent)}</dd><dt>Remaining rate budget</dt><dd>${activeLimit ? amount(budget(w)) : "Rate policy is currently bypassed by opt-out or exemption; debit history is still tracked."}</dd><dt>Recovery reservation</dt><dd>${amount(s.reserved)}</dd><dt>Transfer lock</dt><dd>${s.state.locked ? "Locked" : "Unlocked"}</dd><dt>Containment</dt><dd>${w.guard.paused ? "Fleet paused" : "Fleet not paused"}; wallet ${w.guard.blocked[0] ? "blacklisted" : "not blacklisted"}</dd></dl>
    <p class="hint">Rate budget is not spendable-balance authorization. Balance, reservation, lock, pause, blacklist, enrollment and execution checks can block movement. Rolling accounting retains hourly buckets for 24–25 hours. Top-ups and settings changes do not reset debit history. A lazy basis is fixed by the first successful nonzero debit or explicit owner security action.</p>
    <details><summary>Effective on-chain policy</summary>${policyView(p)}</details><details><summary>Effective and pending governance assignment</summary><p>These exact on-chain assignments differ from profile roles.</p>${json(s.assignment)}${s.pending_assignment ? `<p>Pending nonce ${s.pending_assignment.nonce}; authority epoch ${s.pending_assignment.authority_epoch}.</p><p>Started ${date(unix(s.pending_assignment.proposed_at))}; executable ${timer(s.pending_assignment.executable_at, w.chain_time, sample)}</p>${json(s.pending_assignment.assignment)}` : "<p>No pending governance assignment.</p>"}</details>
    ${s.pending ? `<div class="notice"><h3>Pending wallet change · nonce ${s.pending.nonce}</h3><p>Initiator ${addr(s.pending.initiator)}</p><p>Timer started ${date(unix(s.pending.proposed_at))}; executable ${timer(s.pending.executable_at, w.chain_time, sample)}</p><p>Exact pending payload</p>${json(s.pending.change)}<p>Current policy and lock stay effective until an explicit successful execution. Refresh after the deadline; a countdown cannot execute a change.</p><div class="actions">${btn(context, "Review pending cancellation", "cancel_wallet_change", signing)}${btn(context, "Review pending execution", "execute_wallet_change", signing && s.pending.executable_at * 1000 <= Date.parse(w.chain_time))}</div></div>` : "<p>No pending wallet change in this chain snapshot.</p>"}
    ${!context.connection || context.connection.address !== s.wallet ? '<p class="notice">Connect this exact wallet account to prepare its transactions. Profile membership grants no token authority.</p>' : ""}
    ${!context.me?.chain.gas_price ? '<p class="notice">Operator gas price unavailable. Read-only view; no fee price or denomination will be assumed.</p>' : ""}
    <form id="chain-policy-form"><h3>Change this wallet’s policy</h3><div class="columns"><div><label for="chain-enabled">Rate protection after change</label><select id="chain-enabled" name="enabled" ${attrs(context, signing)}><option value="true" ${p.enabled ? "selected" : ""}>Enabled</option><option value="false" ${!p.enabled ? "selected" : ""}>Opt out after old delay</option></select></div><div><label for="chain-limit">Limit in basis points</label><input id="chain-limit" name="limit_bps" type="number" min="0" max="10000" step="1" required value="${p.limit_bps}" ${attrs(context, signing)}></div><div><label for="chain-relaxation">Relaxation delay in seconds</label><input id="chain-relaxation" name="relaxation_delay" type="number" min="86400" max="31536000" step="1" required value="${p.relaxation_delay}" ${attrs(context, signing)}></div><div><label for="chain-unlock-delay">Unlock delay in seconds</label><input id="chain-unlock-delay" name="unlock_delay" type="number" min="172800" max="31536000" step="1" required value="${p.unlock_delay}" ${attrs(context, signing)}></div></div><p class="hint">Inputs come from the queried effective policy. Any weakening delays the entire exact change under the old delay; tightening applies immediately and invalidates pending wallet changes.</p><button ${attrs(context, signing)}>Simulate policy and review fee</button></form>
    <div class="actions">${btn(context, s.state.locked ? "Review relock and cancel pending" : "Review immediate transfer lock", "lock_wallet", signing && (!s.assignment.protocol || s.assignment.allow_lock))}${btn(context, "Review delayed unlock request", "request_unlock", signing && s.state.locked)}${btn(context, "Review delayed protection rebase", "rebase_protection", signing)}</div>
    ${s.assignment.protocol && !s.assignment.allow_lock ? '<p class="hint">Protocol lock is unavailable: this exact governance assignment does not permit lock enrollment.</p>' : ""}
    <p class="clock-note">Finalized chain snapshot ${e(w.height)} · ${date(w.chain_time)}. Countdown estimates elapsed time from this block timestamp, never your device wall clock. Only refreshed chain state establishes maturity or success.</p></article>`;
}
function recoveryView(context: Context, value: RecoveryRead) {
  const r = value.recovery;
  const current = !r.completed && !r.cancelled && r.replaced_by === null;
  const signer = context.connection?.address;
  const ready =
    !!snapshot &&
    snapshot.contract === value.contract &&
    snapshot.wallet_security.wallet === signer &&
    !!context.me?.chain.gas_price;
  const w = snapshot;
  return `<article class="assignment"><h3>Immutable recovery case · nonce ${r.nonce}</h3><dl><dt>Token</dt><dd>${addr(r.token)}</dd><dt>Source</dt><dd>${addr(r.source)}</dd><dt>Destination</dt><dd>${addr(r.destination)}</dd><dt>Exact amount</dt><dd>${w ? e(formatUnits(r.amount, w.token_info.decimals)) + " " + e(w.token_info.symbol) : e(r.amount) + " base units"} <span class="hint">(${e(r.amount)} base units)</span></dd><dt>Evidence digest</dt><dd><code>${e(r.evidence_hash)}</code></dd><dt>Initiator</dt><dd>${addr(r.initiator)}</dd><dt>Authority epoch</dt><dd>${r.authority_epoch}${w ? ` · current controller epoch ${w.guard.authority_epoch}` : ""}</dd><dt>Timer started</dt><dd>${date(unix(r.proposed_at))}</dd><dt>Contest deadline</dt><dd>${timer(r.executable_at, value.chain_time, recoverySample)}</dd><dt>Acceptance</dt><dd>${r.revoked ? "Permanently revoked for this nonce" : r.accepted ? "Accepted by destination" : "Awaiting destination signature"}</dd><dt>Objection</dt><dd>${r.objected ? (r.objection_resolved ? "Independently resolved" : "Unresolved — execution blocked") : "No source objection recorded"}</dd><dt>Veto</dt><dd>${r.vetoed ? "Vetoed — reservation remains" : "No veto recorded"}</dd><dt>Cancellation</dt><dd>${r.cancelled ? "Cancelled" : r.cancellation_requested ? "Requested; independent second role still required" : "Not requested"}</dd><dt>Execution</dt><dd>${r.completed ? "Completed" : "Not completed"}</dd><dt>Replaced by</dt><dd>${r.replaced_by ?? "No replacement"}</dd></dl>
    ${r.objection_resolution_hash ? `<p>Resolution digest <code>${e(r.objection_resolution_hash)}</code></p>` : ""}
    <p class="notice">Acceptance is not execution. Governance evidence is a trusted attestation, not proof of historical ownership. Deadline expiry, veto, epoch change or objection cannot automatically release reserved funds. Recovery can bypass source pause, blacklist and lock; destination blacklist and all independent authorization checks still apply.</p>
    <div class="actions">${btn(context, "Review exact destination acceptance", "accept_recovery", ready && current && signer === r.destination && !r.revoked && !r.accepted && w?.guard.authority_epoch === r.authority_epoch && !w.guard.blocked[0])}${btn(context, "Review permanent acceptance revocation", "revoke_recovery_acceptance", ready && current && signer === r.destination && !r.revoked)}${btn(context, "Review source objection", "object_recovery", ready && current && signer === r.source && !r.objected)}</div><p class="hint">For acceptance/revocation load the destination wallet; for objection load the source wallet, then connect that exact account. Profile roles and social contacts grant no recovery power. Governance proposal, adjudication, cancellation and recovery-role execution are outside these owner controls.</p><p class="clock-note">Recovery snapshot ${e(value.height)} · ${date(value.chain_time)}. Re-query the nonce after any change.</p></article>`;
}
function reviewView(context: Context) {
  if (!prepared) return "";
  const { intent: i, fee } = prepared;
  return `<section class="panel review" aria-labelledby="chain-review-title"><p class="eyebrow">Exact on-chain transaction review</p><h2 id="chain-review-title" tabindex="-1">${e(i.action.replaceAll("_", " "))}</h2><dl><dt>Chain / ABI source</dt><dd>${e(i.config.chainId)} / <code>${e(i.config.abiSha)}</code></dd><dt>Token / code ID</dt><dd>${addr(i.token.address)} / ${e(i.token.code_id)}</dd><dt>Controller</dt><dd>${addr(i.config.controller)}</dd><dt>Signer</dt><dd>${addr(i.signer)}</dd><dt>Native funds attached</dt><dd>None</dd><dt>Gas limit</dt><dd>${e(fee.gas)} (${prepared.simulatedGas} simulated × ${i.config.gasAdjustment} adjustment, rounded up)</dd><dt>Exact network fee</dt><dd>${fee.amount.map((c) => `${e(c.amount)} ${e(c.denom)} base units`).join(", ")}</dd></dl><p>${e(i.consequences)}</p><p class="notice">This is a direct wallet-signed chain transaction. Network fees may be charged even if execution fails. Simulation does not guarantee success; chain state can change. No server signs or submits it. A fresh API state check is required before and after wallet signing. The wallet must return the exact reviewed message and fee.</p><div class="columns"><div><h3>Current state</h3>${json(i.before)}</div><div><h3>Requested result</h3>${json(i.after)}</div></div><details open><summary>Exact contract execution message</summary>${json(i.msg)}</details><div class="actions">${btn(context, "Sign and broadcast reviewed transaction", "submit")}${btn(context, "Discard transaction review", "discard")}</div></section>`;
}
export function chainView(context: Context): string {
  let c: ChainConfig;
  try {
    c = config(context);
  } catch {
    return `<section id="onchain" class="panel chain" aria-labelledby="chain-title"><div class="row"><h2 id="chain-title">On-chain protection</h2><span class="badge warn">Unavailable</span></div><p>${e(context.me?.chain.status === "unavailable" ? context.me.chain.reason : "Verified deployment configuration, supported ABI source, HTTPS RPC or current service snapshot is unavailable.")}</p><p>No live protection, balances, coverage or effective token settings can be established by this page. Proposed defaults are not effective settings. Existing tokens may be unmigrated; migration status is unknown. RPC health and chain time are unavailable. No chain query or transaction action is enabled.</p>${context.me?.chain.abi_sha ? `<p class="hint">Configured source pin: <code>${e(context.me.chain.abi_sha)}</code>. Unsupported source pins remain gated.</p>` : ""}</section>`;
  }
  if (!c.tokens.some((t) => t.address === token)) {
    token = c.tokens[0]!.address;
    resetChain();
  }
  const wallets = context.me?.wallets.map((w) => w.address) ?? [];
  if (!wallets.includes(wallet)) {
    wallet = wallets.includes(context.connection?.address ?? "")
      ? context.connection!.address
      : (wallets[0] ?? "");
    resetChain();
  }
  return `<section id="onchain" class="panel" aria-labelledby="chain-title"><div class="row"><h2 id="chain-title">On-chain protection</h2><span class="badge">Verified configuration · query required</span></div><p>Only the allowlisted token below is covered by these reads. Native coins, BSC, third-party and unmigrated tokens are not covered. Readiness is not proof that a particular wallet is protected.</p><details><summary>Configured identities</summary><p>Chain ${e(c.chainId)} · controller ${addr(c.controller)}</p><p>Supported source pin <code>${e(c.abiSha)}</code></p></details>
    ${!context.me?.authenticated ? '<p class="notice">Sign in to query chain state through this service. Independently add each wallet to the profile before querying it. Membership permits the read only; wallet signatures establish transaction authority.</p>' : ""}<form id="chain-read-form"><div class="columns"><div><label for="chain-token">Verified token contract</label><select id="chain-token" name="token" ${attrs(context)}>${c.tokens.map((t) => `<option value="${e(t.address)}" ${token === t.address ? "selected" : ""}>${e(t.address)} · code ${e(t.code_id)}</option>`).join("")}</select></div><div><label for="chain-wallet">Wallet to query</label><select id="chain-wallet" name="wallet" ${attrs(context, wallets.length > 0)}>${wallets.length ? wallets.map((w) => `<option value="${e(w)}" ${wallet === w ? "selected" : ""}>${e(w)}</option>`).join("") : '<option value="">Connect a wallet first</option>'}</select></div></div><button ${attrs(context, !!wallet && !!context.me?.authenticated)}>Load authoritative token / wallet state</button></form>
    ${snapshot ? walletView(context, snapshot) : "<p>No chain snapshot loaded. Read effective settings before preparing any change.</p>"}
    <form id="chain-recovery-form"><h3>Read an exact recovery case</h3><label for="chain-nonce">Recovery nonce for this token</label><input id="chain-nonce" name="nonce" type="text" inputmode="numeric" pattern="[0-9]+" autocomplete="off" required value="${caseRead?.recovery.nonce ?? ""}" ${attrs(context)}><p class="hint">The ABI queries one case by nonce. No recovery history or case list is inferred.</p><button ${attrs(context, !!context.me?.authenticated)}>Load authoritative recovery case</button></form>${caseRead ? recoveryView(context, caseRead) : ""}
    ${receipt ? `<div class="notice"><h3>${receipt.code === 0 ? "Transaction included successfully" : "Transaction included but execution failed"}</h3><p>Hash <code>${e(receipt.hash)}</code>; height ${receipt.height}; code ${receipt.code}. ${receipt.code ? "Fees may have been charged. No effective change is assumed." : "Reload the token/wallet and recovery snapshots to inspect the resulting state."}</p></div>` : ""}</section>${reviewView(context)}`;
}
async function readWallet(c: ChainConfig, token: string, wallet: string) {
  return validateWallet(
    await api<WalletRead>(
      `/chain/wallet/${encodeURIComponent(token)}/${encodeURIComponent(wallet)}`,
    ),
    c,
    token,
    wallet,
  );
}
async function readRecovery(c: ChainConfig, token: string, n: number) {
  return validateRecovery(
    await api<RecoveryRead>(
      `/chain/recovery/${encodeURIComponent(token)}/${n}`,
    ),
    c,
    token,
    n,
  );
}
export function bindChain(root: HTMLElement, hooks: Hooks) {
  const select = (nextToken: string, nextWallet: string) => {
    if (nextToken !== token || nextWallet !== wallet) {
      token = nextToken;
      wallet = nextWallet;
      resetChain();
    }
  };
  root
    .querySelector<HTMLFormElement>("#chain-read-form")
    ?.addEventListener("submit", (event) => {
      event.preventDefault();
      const data = new FormData(event.currentTarget as HTMLFormElement);
      select(String(data.get("token")), String(data.get("wallet")));
      void hooks.perform(async () => {
        const c = config(hooks.context());
        resetChain();
        const version = generation;
        const next = await readWallet(c, token, wallet);
        if (version !== generation)
          throw new Error("Selection changed. Reload chain state.");
        snapshot = next;
        sample = performance.now();
        hooks.announce(
          "Authoritative token and wallet snapshot loaded. Review current protections and pending changes.",
        );
      });
    });
  for (const id of ["chain-token", "chain-wallet"])
    root
      .querySelector<HTMLSelectElement>("#" + id)
      ?.addEventListener("change", () => {
        select(
          root.querySelector<HTMLSelectElement>("#chain-token")!.value,
          root.querySelector<HTMLSelectElement>("#chain-wallet")!.value,
        );
        hooks.render();
      });
  root
    .querySelector<HTMLFormElement>("#chain-recovery-form")
    ?.addEventListener("submit", (event) => {
      event.preventDefault();
      const value = String(
        new FormData(event.currentTarget as HTMLFormElement).get("nonce"),
      );
      void hooks.perform(async () => {
        const c = config(hooks.context());
        const n = nonce(value);
        const version = ++generation;
        prepared?.dispose();
        prepared = undefined;
        caseRead = undefined;
        const next = await readRecovery(c, token, n);
        if (version !== generation)
          throw new Error("Selection changed. Reload the case.");
        caseRead = next;
        recoverySample = performance.now();
        hooks.announce(
          "Exact recovery case loaded. Acceptance and execution are separate.",
        );
      });
    });
  const prepare = async (action: Action, policy?: Policy) => {
    const context = hooks.context(),
      c = config(context),
      conn = context.connection;
    if (!snapshot || !conn || conn.address !== wallet)
      throw new Error(
        "Load this wallet’s chain state and connect the same account first.",
      );
    prepared?.dispose();
    prepared = undefined;
    receipt = undefined;
    const i = makeIntent(c, snapshot, conn.address, action, policy, caseRead);
    const version = ++generation;
    hooks.announce(
      "Verifying RPC identities and simulating the exact transaction. No wallet signature requested yet.",
    );
    const next = await prepareTransaction(i, conn);
    if (version !== generation) {
      next.dispose();
      throw new Error("Wallet or selection changed. Prepare a fresh review.");
    }
    prepared = next;
    hooks.announce(
      "Simulation complete. Review the exact old/new state, message, gas and fee before signing.",
    );
  };
  root
    .querySelector<HTMLFormElement>("#chain-policy-form")
    ?.addEventListener("submit", (event) => {
      event.preventDefault();
      const data = new FormData(event.currentTarget as HTMLFormElement);
      const p: Policy = {
        enabled: data.get("enabled") === "true",
        limit_bps: Number(data.get("limit_bps")),
        relaxation_delay: Number(data.get("relaxation_delay")),
        unlock_delay: Number(data.get("unlock_delay")),
      };
      void hooks
        .perform(() => prepare("set_wallet_policy", p))
        .then(() =>
          root.querySelector<HTMLElement>("#chain-review-title")?.focus(),
        );
    });
  root
    .querySelectorAll<HTMLButtonElement>("[data-chain-action]")
    .forEach((button) =>
      button.addEventListener("click", () => {
        const action = button.dataset.chainAction!;
        if (action === "discard") {
          generation++;
          prepared?.dispose();
          prepared = undefined;
          hooks.render();
          hooks.announce(
            "Transaction review discarded. No wallet signature requested.",
          );
          return;
        }
        void hooks
          .perform(async () => {
            if (action !== "submit") return prepare(action as Action);
            const selected = prepared;
            if (!selected)
              throw new Error("Prepare a fresh transaction review.");
            const version = generation;
            const check = async () => {
              const c = config(hooks.context());
              if (
                version !== generation ||
                c.abiSha !== selected.intent.config.abiSha ||
                JSON.stringify(c) !== JSON.stringify(selected.intent.config)
              )
                throw new Error("Configuration changed.");
              const fresh = await readWallet(
                c,
                selected.intent.token.address,
                selected.intent.signer,
              );
              if (fingerprint(fresh) !== fingerprint(selected.intent.wallet))
                throw new Error("Reviewed wallet state changed.");
              if (selected.intent.recovery) {
                const latest = await readRecovery(
                  c,
                  selected.intent.token.address,
                  selected.intent.recovery.recovery.nonce,
                );
                if (
                  fingerprint(latest) !== fingerprint(selected.intent.recovery)
                )
                  throw new Error("Recovery case changed.");
              }
              if (version !== generation) throw new Error("Selection changed.");
            };
            hooks.announce(
              "Checking fresh chain state, then waiting for your wallet to sign the exact reviewed transaction.",
            );
            try {
              receipt = await selected.submit(check);
              hooks.announce(
                receipt.code === 0
                  ? "Transaction included successfully. Reload authoritative chain state to inspect its effect."
                  : "Transaction included but execution failed. Fees may have been charged; reload state before retrying.",
                receipt.code !== 0,
              );
            } finally {
              prepared = undefined;
              snapshot = undefined;
              caseRead = undefined;
              generation++;
            }
          })
          .then(() =>
            root.querySelector<HTMLElement>("#chain-review-title")?.focus(),
          );
      }),
    );
}
export function tickChain(root: HTMLElement) {
  root
    .querySelectorAll<HTMLElement>("[data-chain-deadline]")
    .forEach((node) => {
      const now =
        Date.parse(node.dataset.chainTime!) +
        performance.now() -
        Number(node.dataset.chainSample);
      node.textContent = remaining(node.dataset.chainDeadline!, now).replace(
        "server status",
        "chain status",
      );
    });
}
