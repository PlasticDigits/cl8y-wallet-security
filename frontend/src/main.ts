import "./style.css";
import { bindChain, chainView, resetChain, tickChain } from "./chain-ui";
import { api, ApiError, assertMe, setCsrf } from "./api";
import type { Assignment, Challenge, Me, Role, ServiceStatus } from "./api";
import { checkAccount, connect, validateSignature } from "./wallet";
import type { Connection, WalletKind } from "./wallet";
import { date, escapeHtml as e, remaining } from "./format";

type Proof = {
  challenge: Challenge;
  purpose: string;
  address: string;
  connection: Connection;
};
type Review =
  | { kind: "proposal"; candidate: string; role: Role }
  | { kind: "cancel"; assignment: Assignment }
  | { kind: "contact"; id: string };
const root = document.querySelector<HTMLElement>("#main")!;
const feedback = document.querySelector<HTMLElement>("#feedback")!;
let me: Me | undefined;
let status: ServiceStatus | undefined;
let connection: Connection | undefined;
let proof: Proof | undefined;
let review: Review | undefined;
let busy = false;
let stale = false;
let revision = 0;
let sampledTime: { server: number; monotonic: number } | undefined;
let lastRefresh: string | undefined;
let pairing: { url: string } | undefined;

function announce(message: string, error = false) {
  feedback.textContent = message;
  feedback.classList.toggle("error", error);
}
function now() {
  return sampledTime
    ? sampledTime.server + performance.now() - sampledTime.monotonic
    : Date.now();
}
function button(label: string, action: string, extra = "") {
  return `<button type="button" data-action="${action}" ${extra} ${busy ? "disabled" : ""}>${label}</button>`;
}
function address(value: string) {
  return `<span class="address">${e(value)}</span>`;
}
function badge(value: string, tone = "") {
  return `<span class="badge ${tone}">${e(value)}</span>`;
}
function deadline(value: string) {
  return `<time datetime="${e(value)}">${date(value)}</time><span class="countdown" data-deadline="${e(value)}">${e(remaining(value, now()))}</span>`;
}
function canWrite() {
  return !!me?.authenticated && !stale;
}
function requireWrite() {
  if (!canWrite())
    throw new Error("Refresh and sign in before making profile changes.");
}
function invalidateProof() {
  resetChain();
  revision++;
  proof = undefined;
}

async function refresh() {
  const next = assertMe(await api<Me>("/me"));
  invalidateProof();
  review = undefined;
  if (
    me?.profile_id !== next.profile_id ||
    me?.chain.chain_id !== next.chain.chain_id
  ) {
    invalidateProof();
    review = undefined;
    pairing = undefined;
  }
  me = next;
  setCsrf(next.csrf_token ?? "");
  const time = Date.parse(next.server_time ?? "");
  sampledTime = Number.isFinite(time)
    ? { server: time, monotonic: performance.now() }
    : undefined;
  stale = false;
  lastRefresh = next.server_time;
  try {
    status = await api<ServiceStatus>("/status");
  } catch {
    status = undefined;
  }
}
async function run(task: () => Promise<void>, success?: string) {
  if (busy) return;
  busy = true;
  render();
  try {
    await task();
    if (success) announce(success);
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) {
      me = undefined;
      connection = undefined;
      invalidateProof();
      review = undefined;
      pairing = undefined;
      setCsrf("");
    }
    announce(
      error instanceof Error
        ? error.message
        : "The action could not be confirmed. Refresh before retrying.",
      true,
    );
  } finally {
    busy = false;
    render();
  }
}
async function mutate(path: string, body: unknown) {
  requireWrite();
  try {
    await api<unknown>(path, body);
  } catch (error) {
    stale = true;
    throw error;
  }
  invalidateProof();
  review = undefined;
  try {
    await refresh();
  } catch {
    stale = true;
    throw new Error(
      "The request was accepted, but the updated snapshot could not be loaded. Refresh before making further changes.",
    );
  }
}
async function prepare(purpose: string, expected?: string) {
  if (!me || stale)
    throw new Error("Refresh the service snapshot before requesting a proof.");
  if (!connection)
    throw new Error("Connect the wallet that will sign this proof first.");
  if (purpose !== "login") requireWrite();
  if (expected && connection.address !== expected)
    throw new Error(
      "Select the candidate account in your wallet and reconnect. The owner cannot sign consent for the candidate.",
    );
  if (
    purpose === "add_wallet" &&
    me.wallets.some((w) => w.address === connection!.address)
  )
    throw new Error(
      "This wallet already belongs to your profile. Select another account and reconnect.",
    );
  invalidateProof();
  review = undefined;
  const version = revision;
  const selected = connection;
  await checkAccount(selected, selected.address);
  const challenge = await api<Challenge>("/auth/challenge", {
    address: selected.address,
    purpose,
  });
  if (version !== revision)
    throw new Error("Wallet selection changed. Request a fresh challenge.");
  if (
    !challenge.id ||
    typeof challenge.message !== "string" ||
    challenge.chain_id !== selected.chainId ||
    !Number.isFinite(Date.parse(challenge.expires_at))
  )
    throw new Error(
      "The service returned an unsupported or mismatched challenge. Nothing was signed.",
    );
  proof = {
    challenge,
    purpose,
    address: selected.address,
    connection: selected,
  };
  announce(
    "Challenge ready. Review its purpose, account and exact message, then choose Sign proof.",
  );
}
async function sign() {
  const selected = proof;
  if (!selected) throw new Error("Request a new challenge first.");
  const version = revision;
  if (Date.parse(selected.challenge.expires_at) <= now()) {
    invalidateProof();
    throw new Error(
      "The challenge expired. Request a fresh challenge; no profile change was confirmed.",
    );
  }
  await checkAccount(selected.connection, selected.address);
  announce(
    "Waiting for the wallet signature. Review the message in your wallet.",
  );
  let signature;
  try {
    signature = await selected.connection.wallet.signArbitrary(
      selected.challenge.chain_id,
      selected.address,
      selected.challenge.message,
    );
  } catch {
    throw new Error(
      "Wallet signing was declined or is unsupported. No proof was submitted. You can request a fresh challenge.",
    );
  }
  if (version !== revision)
    throw new Error(
      "The wallet changed while signing. The proof was discarded.",
    );
  await checkAccount(selected.connection, selected.address);
  validateSignature(signature);
  if (Date.parse(selected.challenge.expires_at) <= now()) {
    invalidateProof();
    throw new Error(
      "The challenge expired during signing. Request a fresh challenge.",
    );
  }
  // The API verifies the canonical document, address binding, purpose, session and one-use nonce.
  const result = await api<{ csrf_token?: string; verified?: boolean }>(
    "/auth/verify",
    {
      id: selected.challenge.id,
      public_key: signature.pub_key.value,
      signature: signature.signature,
    },
  );
  if (
    selected.purpose === "login" ? !result.csrf_token : result.verified !== true
  ) {
    invalidateProof();
    throw new Error(
      "The service did not confirm the proof. Refresh your session before retrying.",
    );
  }
  if (result.csrf_token) setCsrf(result.csrf_token);
  invalidateProof();
  try {
    await refresh();
  } catch {
    stale = true;
    throw new Error(
      "Proof accepted, but the updated session could not be loaded. Refresh before continuing.",
    );
  }
  announce(
    selected.purpose === "login"
      ? "Signed in with a verified wallet."
      : selected.purpose === "add_wallet"
        ? "Independent wallet proof accepted. Portfolio refreshed."
        : "Candidate consent accepted. The server will activate the role only after its deadline.",
  );
}
function proofView() {
  if (!proof) return "";
  const assignment = me?.assignments.find(
    (a) => proof!.purpose === "assignment:" + a.id,
  );
  const purpose =
    proof.purpose === "login"
      ? "Sign in to this profile"
      : proof.purpose === "add_wallet"
        ? "Add this independently verified wallet"
        : "Consent to the exact proposed profile role";
  return `<section class="panel review" aria-labelledby="proof-title"><p class="eyebrow">Review before signing</p><h2 id="proof-title" tabindex="-1">${purpose}</h2>
    <dl><dt>Signer</dt><dd>${address(proof.address)}</dd><dt>Chain</dt><dd>${e(proof.challenge.chain_id)}</dd><dt>Website</dt><dd>${e(location.origin)}</dd><dt>Purpose</dt><dd>${e(proof.purpose)}</dd><dt>Expires</dt><dd>${deadline(proof.challenge.expires_at)}</dd>${assignment ? `<dt>Candidate role</dt><dd>${e(assignment.role)}</dd><dt>Owner</dt><dd>${address(assignment.owner_wallet)}</dd><dt>Activation deadline</dt><dd>${deadline(assignment.executable_at)}</dd>` : ""}</dl>
    <p class="hint">Expiry countdown uses ${sampledTime ? "a server database time sample" : "your device clock, which may be inaccurate"}. The server enforces expiry. If time runs out, request a fresh challenge.</p>
    <p>This off-chain ADR-036 proof changes profile identity or consent only. It transfers no tokens, pays no fee, and grants no on-chain recovery or spending authority.</p>
    <details open><summary>Exact message sent to your wallet</summary><pre>${e(proof.challenge.message)}</pre></details>
    <div class="actions">${button("Sign proof", "sign", 'class="primary"')}${button("Discard challenge", "discard-proof")}</div>
  </section>`;
}
function reviewView() {
  if (!review) return "";
  let content = "";
  if (review.kind === "proposal") {
    content = `<h2 id="review-title" tabindex="-1">Propose a ${e(review.role)} role</h2><dl><dt>Owner</dt><dd>${address(me!.anchor_wallet!)}</dd><dt>Candidate</dt><dd>${address(review.candidate)}</dd><dt>Current role</dt><dd>Existing assignments remain as shown below.</dd><dt>New proposal</dt><dd>${e(review.role)}; awaiting independent candidate consent and the full profile delay (at least 24 hours).</dd></dl><p>The server sets the start and exact deadline when it accepts this request. This does not replace or remove another role. Replacement requires a new immutable proposal and full delay. Profile roles confer no token authority.</p>`;
  } else if (review.kind === "cancel") {
    const item = review.assignment;
    content = `<h2 id="review-title" tabindex="-1">${item.status === "active" ? "Schedule role removal" : "Cancel role proposal"}</h2><dl><dt>Candidate</dt><dd>${address(item.candidate_wallet)}</dd><dt>Role</dt><dd>${e(item.role)}</dd><dt>Current state</dt><dd>${e(item.status)}</dd><dt>After this request</dt><dd>${item.status === "active" ? "Removal will be delayed by the server. The active role remains effective until the removal deadline." : "This proposal will be cancelled. It will not become active."}</dd></dl><p>The server's current state determines cancellation versus delayed removal. If a pending role became active since the snapshot, removal is delayed and the role stays effective meanwhile. This changes only the profile assignment. No token is unlocked or recovered, and no on-chain role is removed.</p>`;
  } else {
    content = `<h2 id="review-title" tabindex="-1">Schedule notification contact removal</h2><p>For a verified contact, the server starts a removal delay and attempts to warn existing verified contacts. It remains effective until the deadline. An unverified contact can be removed immediately. Delivery depends on provider readiness; this request cannot confirm that a warning reached its recipient. Wallet and token authority are unchanged.</p>`;
  }
  return `<section class="panel review" aria-labelledby="review-title"><p class="eyebrow">Review profile change</p>${content}<div class="actions">${button("Confirm profile change", "confirm-review", 'class="primary"')}${button("Keep current state", "discard-review")}</div></section>`;
}
function assignmentView(item: Assignment) {
  const final = item.status === "cancelled" || item.status === "removed";
  const removal = item.status === "active" && item.removal_at;
  return `<article class="assignment"><div class="row"><h3>${e(item.role)}</h3>${badge(removal ? "Active · removal scheduled" : item.status.replaceAll("_", " "), item.status === "active" ? "good" : "")}</div>
    <p>Candidate ${address(item.candidate_wallet)}</p><details><summary>Owner and proposal identity</summary><p>Owner ${address(item.owner_wallet)}</p><p>Proposal <code>${e(item.id)}</code></p></details>
    <dl><dt>Timer started</dt><dd><time datetime="${e(item.proposed_at)}">${date(item.proposed_at)}</time></dd><dt>Activation deadline</dt><dd>${deadline(item.executable_at)}</dd><dt>Delay snapshot</dt><dd>${e(item.delay_seconds)} seconds</dd><dt>Candidate consent</dt><dd>${item.accepted_at ? date(item.accepted_at) : "Not yet received — owner signature is insufficient"}</dd>${removal ? `<dt>Removal deadline</dt><dd>${deadline(item.removal_at!)}</dd>` : ""}</dl>
    ${removal ? '<p class="notice">This profile role remains active during removal. The server confirms when removal takes effect.</p>' : ""}
    <div class="actions">${!item.accepted_at && !final ? button("Review candidate consent", "consent", `data-id="${e(item.id)}" ${!canWrite() ? "disabled" : ""}`) : ""}
    ${!final && !removal ? button(item.status === "active" ? "Review delayed removal" : "Review cancellation", "cancel-assignment", `data-id="${e(item.id)}" ${!canWrite() ? "disabled" : ""}`) : ""}</div></article>`;
}
function deliveryStatus(): string {
  const notifications = status?.notifications;
  if (
    typeof notifications === "object" &&
    notifications !== null &&
    "delivery_enabled" in notifications
  ) {
    return `Email: ${"email_ready" in notifications && notifications.email_ready === true ? "ready" : "unavailable"}. Telegram: ${"telegram_ready" in notifications && notifications.telegram_ready === true ? "ready" : "unavailable"}. ${notifications.delivery_enabled === true ? "Delivery providers are enabled; queued requests are not proof of receipt." : "Notification delivery is disabled. A verification or warning cannot be assumed sent."}`;
  }
  return "Notification delivery readiness is unavailable. No verification or warning is confirmed sent.";
}
function workerStatusView(): string {
  const worker = status?.worker;
  if (!worker || typeof worker !== "object")
    return '<p class="hint">Notification worker status is unavailable. Warning delivery is not confirmed.</p>';
  const record = worker as Record<string, unknown>;
  const detail =
    record.detail && typeof record.detail === "object"
      ? (record.detail as Record<string, unknown>)
      : {};
  const labels: Record<string, string> = {
    pending: "queued notices",
    failed: "failed notices",
    controller_fanout_pending: "controller fanout jobs",
    verification_rejections: "verification rejections",
  };
  const backlog = Object.entries(labels).flatMap(([key, label]) => {
    const count = detail[key];
    return typeof count === "number" && Number.isSafeInteger(count) && count > 0
      ? [`${count} ${label}`]
      : [];
  });
  const oldest =
    typeof detail.oldest_pending === "string"
      ? date(detail.oldest_pending)
      : undefined;
  return `${backlog.length ? `<p class="notice">Notification processing requires attention: ${e(backlog.join("; "))}. Delivery may be delayed or have failed.${oldest ? ` Oldest pending: ${e(oldest)}.` : ""}</p>` : ""}<p class="hint">Worker last reported: ${typeof record.last_seen === "string" ? date(record.last_seen) : "unavailable"}.${typeof record.source_sha === "string" && /^[a-f0-9]{40,64}$/.test(record.source_sha) ? ` Worker source: <code>${e(record.source_sha)}</code>.` : ""} This report is not proof of recipient delivery.</p>`;
}
function contactsView() {
  return `<section id="contacts" class="panel" aria-labelledby="contacts-title"><p class="eyebrow">Stay informed</p><h2 id="contacts-title">Notification contacts</h2><p class="notice">${deliveryStatus()}</p>${workerStatusView()}<p>Contacts receive warnings only. Email or Telegram possession grants no wallet ownership, guardian or recovery authority. Destinations are kept private and are never listed here.</p>
    ${me?.contacts.length ? `<ul class="contacts">${me.contacts.map((c) => `<li><div><strong>${e(c.kind)}</strong> ${badge(c.status)}${c.activation_at && c.status === "pending" ? `<p>Replacement contact pending; the previous verified contact remains effective. Activation ${deadline(c.activation_at)}</p>` : ""}${c.removal_at ? `<p>${c.status === "removed" ? "Removed by the server; removal deadline was" : "Removal scheduled; the verified contact stays effective until"} ${deadline(c.removal_at)}</p>` : ""}</div>${!c.removal_at && c.status !== "removed" ? button("Review contact removal", "remove-contact", `data-id="${e(c.id)}" ${!canWrite() ? "disabled" : ""}`) : ""}</li>`).join("")}</ul>` : "<p>No notification contacts in this snapshot.</p>"}
    <div class="columns"><form id="email-form"><h3>Verify an email address</h3><label for="email">Email address</label><input id="email" name="email" type="email" maxlength="254" autocomplete="off" required ${!canWrite() || busy ? "disabled" : ""}><p class="hint">Requests double opt-in. Check readiness above; acceptance alone does not mean an email was sent.</p><button ${!canWrite() || busy ? "disabled" : ""}>Request email verification</button></form>
    <form id="email-verify-form"><h3>Complete email verification</h3><label for="email-token">One-use verification token</label><input id="email-token" name="token" type="password" autocomplete="off" spellcheck="false" maxlength="1024" required ${!canWrite() || busy ? "disabled" : ""}><p class="hint">Paste a token received through the verification channel. It is never stored in this browser.</p><button ${!canWrite() || busy ? "disabled" : ""}>Verify email token</button></form></div>
    <h3>Verify Telegram</h3><p>Request a one-use bot pairing. Only use pairing details returned by the service. Starting pairing does not confirm delivery or verification.</p>${button("Request Telegram pairing", "telegram", !canWrite() ? "disabled" : "")}
    ${pairing ? `<div class="notice"><p>Pairing requested. Complete it with the configured bot, then refresh contact status.</p>${pairing.url ? `<p><a href="${e(pairing.url)}" target="_blank" rel="noreferrer noopener">Open Telegram bot pairing</a></p>` : ""}</div>` : ""}
    <form id="telegram-confirm-form"><label for="telegram-token">Telegram confirmation code</label><input id="telegram-token" name="token" type="password" autocomplete="off" spellcheck="false" maxlength="1024" required ${!canWrite() || busy ? "disabled" : ""}><p class="hint">After starting the configured bot, paste its one-use code here to confirm control.</p><button ${!canWrite() || busy ? "disabled" : ""}>Confirm Telegram code</button></form>
    ${!me?.authenticated ? "<p>Sign in to manage verification and contact preferences.</p>" : ""}</section>`;
}
function render() {
  const focusId = document.activeElement?.id;
  document.querySelector("#network")!.textContent = me?.chain.chain_id
    ? `Terra Classic · ${me.chain.chain_id}`
    : "Service unavailable";
  root.innerHTML = `<div class="page-title"><div><p class="eyebrow">Your wallet, your control</p><h1>Wallet security</h1><p>Verified identity. Visible delays. Clear authority.</p></div><div class="actions">${button("Refresh status", "refresh")}${me?.authenticated ? button("Sign out", "logout") : ""}</div></div>
    ${stale ? '<p class="notice danger">This snapshot is stale. Profile changes are blocked until you refresh successfully.</p>' : ""}
    ${chainView({ me, connection, busy, stale })}
    <section class="panel" aria-labelledby="identity-title"><div class="row"><h2 id="identity-title">${me?.authenticated ? "Verified profile" : "Connect and prove your wallet"}</h2>${badge(me?.authenticated ? "Signed in" : "Signed out", me?.authenticated ? "good" : "")}</div>
    ${me?.authenticated ? `<p>Immutable login anchor ${address(me.anchor_wallet!)}</p><p>Changing the extension account does not change this profile. Each added wallet proves its own control.</p>` : "<p>Connect a Terra Classic wallet, then review and sign a one-use ADR-036 challenge to sign in. An address alone cannot authenticate you.</p>"}
    <form id="connect-form"><label for="provider">Injected wallet</label><div class="actions"><select id="provider" name="provider" ${busy ? "disabled" : ""}><option value="keplr" ${connection?.kind === "keplr" ? "selected" : ""}>Keplr-compatible injected provider</option><option value="station" ${connection?.kind === "station" ? "selected" : ""}>Station (Keplr bridge)</option></select><button ${busy || !me || stale ? "disabled" : ""}>Connect selected wallet</button></div></form>
    ${connection ? `<p>Selected extension account ${address(connection.address)}</p><div class="actions">${!me?.authenticated ? button("Review sign-in challenge", "login", stale ? "disabled" : "") : button("Review add-wallet proof", "add-wallet", stale ? "disabled" : "")}${button("Disconnect selection", "disconnect")}</div>` : ""}
    <p class="hint">Requires an injected provider with enable, getKey and signArbitrary, a configured Terra Classic account, and secp256k1 ADR-036 support. Mobile WalletConnect, legacy Station without this bridge, and unsupported hardware signing are unavailable. An injected provider may be supplied by another compatible extension.</p></section>
    ${proofView()}${reviewView()}
    <section id="portfolio" class="panel" aria-labelledby="portfolio-title"><div class="row"><div><p class="eyebrow">Multiwallet portfolio</p><h2 id="portfolio-title">Verified wallets</h2></div>${badge(`${me?.wallets.length ?? 0} wallets`)}</div>
    ${me?.wallets.length ? `<ul class="wallets">${me.wallets.map((w) => `<li><div>${address(w.address)}<p class="hint">Control verified ${date(w.verified_at)}</p></div>${badge(w.address === me!.anchor_wallet ? "Login anchor" : "Added wallet")}</li>`).join("")}</ul>` : "<p>No verified wallet portfolio loaded. Sign in to see your wallets.</p>"}
    <p>Wallet membership is an off-chain record. Use allowlisted chain reads above to inspect a token and wallet; profile membership establishes no token coverage.</p>
    <div class="capabilities"><article><h3>Rate limits</h3><p>Read effective and pending policy from the chain; weakening requires the old delay.</p></article><article><h3>Transfer lock</h3><p>Chain controls require a verified deployment and the exact owner wallet.</p></article><article><h3>Recovery & disputes</h3><p>Read an exact case nonce; acceptance, objection and execution have separate authority.</p></article></div><p class="hint">Transaction controls remain gated until verified deployment identities, the supported ABI source and authoritative chain reads are available. Amounts and old/new settings are never inferred.</p></section>
    <section id="roles" class="panel" aria-labelledby="roles-title"><p class="eyebrow">Independent consent</p><h2 id="roles-title">Profile wallet roles</h2><p>Guardian, recovery and notification roles here are profile records. They cannot unlock, transfer or recover tokens. Consent and the full server delay are both required for activation.</p>
    <form id="assignment-form"><div class="columns"><div><label for="candidate">Candidate Terra Classic address</label><input id="candidate" name="candidate" autocomplete="off" spellcheck="false" maxlength="90" pattern="terra1[a-z0-9]+" required ${!canWrite() || busy ? "disabled" : ""}></div><div><label for="role">Profile role</label><select id="role" name="role" ${!canWrite() || busy ? "disabled" : ""}><option value="guardian">Guardian</option><option value="recovery">Recovery</option><option value="notification">Notification</option></select></div></div><p class="hint">First propose the exact candidate and role. Then select that candidate account in the extension, reconnect, and obtain its independent consent proof.</p><button ${!canWrite() || busy ? "disabled" : ""}>Review role proposal</button></form>
    <p class="clock-note">${sampledTime ? "Profile countdowns estimate elapsed time from the API database timestamp; token controls use separate finalized chain snapshots when available." : "Server time unavailable: countdowns use your device clock and may be inaccurate."} Only the server confirms activation or removal. ${lastRefresh ? `Snapshot: ${date(lastRefresh)}.` : ""} Refresh after a deadline.</p>
    <div class="assignments">${me?.assignments.length ? me.assignments.map(assignmentView).join("") : "<p>No profile role assignments in this snapshot.</p>"}</div></section>
    ${contactsView()}
    <aside class="panel trust"><h2>Authority and recovery</h2><p>Trusted CL8Y governance is a trust assumption. Containment, unpause, recovery authorization, execution and key rotation are separate powers. A social account or contact alone cannot establish asset ownership. Only an authoritative chain query establishes the state of a specific recovery case; no case history is inferred.</p></aside>`;
  root.setAttribute("aria-busy", String(busy));
  bind();
  bindChain(root, {
    context: () => ({ me, connection, busy, stale }),
    perform: run,
    announce,
    render,
  });
  if (focusId) document.getElementById(focusId)?.focus();
}
function focusReview() {
  document.querySelector<HTMLElement>("#proof-title, #review-title")?.focus();
}
function bind() {
  root.querySelectorAll<HTMLButtonElement>("[data-action]").forEach((b) =>
    b.addEventListener("click", () => {
      const action = b.dataset.action;
      if (action === "discard-proof" || action === "disconnect") {
        invalidateProof();
        if (action === "disconnect") connection = undefined;
        announce(
          "Wallet selection or challenge cleared. Your server session is unchanged.",
        );
        render();
        return;
      }
      if (action === "discard-review") {
        review = undefined;
        render();
        return;
      }
      if (action === "cancel-assignment") {
        const assignment = me?.assignments.find((a) => a.id === b.dataset.id);
        if (assignment) {
          proof = undefined;
          review = { kind: "cancel", assignment };
          render();
          focusReview();
        }
        return;
      }
      if (action === "remove-contact") {
        proof = undefined;
        review = { kind: "contact", id: b.dataset.id! };
        render();
        focusReview();
        return;
      }
      void run(async () => {
        if (action === "refresh") {
          try {
            await refresh();
            announce("Session and profile status refreshed.");
          } catch (error) {
            stale = true;
            throw error;
          }
        }
        if (action === "login" || action === "add-wallet")
          await prepare(action === "login" ? "login" : "add_wallet");
        if (action === "sign") await sign();
        if (action === "consent") {
          const assignment = me?.assignments.find((a) => a.id === b.dataset.id);
          if (!assignment)
            throw new Error("Refresh the assignment snapshot first.");
          await prepare(
            "assignment:" + assignment.id,
            assignment.candidate_wallet,
          );
        }
        if (action === "confirm-review") {
          const selected = review;
          if (!selected) return;
          if (selected.kind === "proposal")
            await mutate("/assignments", {
              candidate_wallet: selected.candidate,
              role: selected.role,
            });
          else if (selected.kind === "cancel")
            await mutate(
              "/assignments/" +
                encodeURIComponent(selected.assignment.id) +
                "/cancel",
              {},
            );
          else
            await mutate(
              "/contacts/" + encodeURIComponent(selected.id) + "/remove",
              {},
            );
          announce(
            "Profile change accepted. Refreshed server status is shown below.",
          );
        }
        if (action === "logout") {
          await api("/auth/logout", {});
          me = undefined;
          status = undefined;
          connection = undefined;
          pairing = undefined;
          review = undefined;
          invalidateProof();
          setCsrf("");
          announce("Signed out. Server session revoked.");
          await refresh();
        }
        if (action === "telegram") {
          requireWrite();
          pairing = undefined;
          const response = await api<Record<string, unknown>>(
            "/contacts/telegram",
            {},
          );
          // Only the API supplies the configured bot URL. Reject unsafe protocol/host/path.
          if (typeof response.pairing_url === "string") {
            let url: URL | undefined;
            try {
              url = new URL(response.pairing_url);
            } catch {
              /* Leave pairing unavailable. */
            }
            if (
              url?.protocol === "https:" &&
              url.hostname === "t.me" &&
              !url.port &&
              !url.username &&
              !url.password &&
              /^\/[A-Za-z0-9_]+$/.test(url.pathname) &&
              url.searchParams.has("start")
            )
              pairing = { url: url.href };
          }
          announce(
            "Telegram pairing request accepted. No delivery or verification is confirmed; complete service-provided pairing and refresh.",
          );
        }
      }).then(focusReview);
    }),
  );
  root
    .querySelector<HTMLFormElement>("#connect-form")
    ?.addEventListener("submit", (event) => {
      event.preventDefault();
      const kind = new FormData(event.currentTarget as HTMLFormElement).get(
        "provider",
      ) as WalletKind;
      void run(async () => {
        invalidateProof();
        connection = undefined;
        if (!me || stale)
          throw new Error("Refresh the service snapshot first.");
        const version = revision;
        const next = await connect(kind, me.chain.chain_id);
        if (version !== revision)
          throw new Error(
            "Wallet account changed during connection. Reconnect.",
          );
        connection = next;
        announce(
          "Wallet connected. Control is established only after the signed challenge is verified.",
        );
      });
    });
  root
    .querySelector<HTMLFormElement>("#assignment-form")
    ?.addEventListener("submit", (event) => {
      event.preventDefault();
      const data = new FormData(event.currentTarget as HTMLFormElement);
      const candidate = String(data.get("candidate") ?? "").trim();
      const role = String(data.get("role")) as Role;
      if (candidate === me?.anchor_wallet) {
        announce(
          "The candidate must be independent from the login anchor.",
          true,
        );
        return;
      }
      invalidateProof();
      review = { kind: "proposal", candidate, role };
      render();
      focusReview();
    });
  root
    .querySelector<HTMLFormElement>("#email-form")
    ?.addEventListener("submit", (event) => {
      event.preventDefault();
      const form = event.currentTarget as HTMLFormElement;
      const email = String(new FormData(form).get("email") ?? "");
      form.reset();
      void run(async () => {
        requireWrite();
        const result = await api<Record<string, unknown>>("/contacts/email", {
          address: email,
        });
        announce(
          result.queued === true && result.sent === false
            ? "Email verification queued. Delivery is not yet confirmed; verification requires the one-use token."
            : "Email verification request accepted. The service has not confirmed delivery; do not assume a message was sent.",
        );
        try {
          await refresh();
        } catch {
          stale = true;
        }
      });
    });
  root
    .querySelector<HTMLFormElement>("#telegram-confirm-form")
    ?.addEventListener("submit", (event) => {
      event.preventDefault();
      const form = event.currentTarget as HTMLFormElement;
      const token = String(new FormData(form).get("token") ?? "");
      form.reset();
      void run(async () => {
        await mutate("/contacts/telegram/confirm", { token });
        pairing = undefined;
        announce(
          "Telegram confirmation accepted. The refreshed contact status is authoritative.",
        );
      });
    });
  root
    .querySelector<HTMLFormElement>("#email-verify-form")
    ?.addEventListener("submit", (event) => {
      event.preventDefault();
      const form = event.currentTarget as HTMLFormElement;
      const token = String(new FormData(form).get("token") ?? "");
      form.reset();
      void run(async () => {
        await mutate("/contacts/email/verify", { token });
        announce(
          "Email verification request accepted. The refreshed contact status is authoritative.",
        );
      });
    });
}
for (const event of ["keplr_keystorechange", "station_wallet_change"]) {
  window.addEventListener(event, () => {
    invalidateProof();
    connection = undefined;
    announce(
      "The extension account changed. Reconnect before requesting a new proof. The signed-in profile remains unchanged.",
    );
    render();
  });
}
window.addEventListener("pageshow", (event) => {
  if (event.persisted) {
    invalidateProof();
    connection = undefined;
    stale = true;
    render();
    announce("Page restored. Refresh to load current server status.");
  }
});
setInterval(() => {
  tickChain(root);
  root.querySelectorAll<HTMLElement>("[data-deadline]").forEach((node) => {
    node.textContent = remaining(node.dataset.deadline!, now());
  });
}, 1000);
void run(async () => {
  try {
    await refresh();
    announce(
      me?.authenticated
        ? "Session restored from the service."
        : "Connect a wallet to get started.",
    );
  } catch (error) {
    stale = true;
    throw error;
  }
});
