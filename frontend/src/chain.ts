import type { ChainStatus } from "./api";

// Types follow contract src/{msg,security,recovery}.rs and security-interface v1.
// This pin is updated only after the contract lead publishes the reviewed final schema.
export const SUPPORTED_ABI_SHA = "2d70d43c651ecd4491c0736c89ae2975ee825686";
export type Policy = {
  enabled: boolean;
  limit_bps: number;
  relaxation_delay: number;
  unlock_delay: number;
};
export type ChainAssignment = {
  protocol: boolean;
  exempt: boolean;
  allow_lock: boolean;
  evidence_hash: string;
};
export type Pending = {
  nonce: number;
  initiator: string;
  proposed_at: number;
  executable_at: number;
  change: "unlock" | { policy: Policy } | { rebase: string };
};
export type WalletSecurity = {
  wallet: string;
  initialized: boolean;
  state: {
    policy: Policy;
    protected_balance: string;
    locked: boolean;
    buckets: { hour: number; amount: string }[];
  };
  pending: Pending | null;
  assignment: ChainAssignment;
  pending_assignment:
    | (Omit<Pending, "change"> & {
        authority_epoch: number;
        assignment: ChainAssignment;
      })
    | null;
  reserved: string;
  rolling_spent: string;
};
export type Guard = {
  interface_version: number;
  epoch: number;
  authority_epoch: number;
  paused: boolean;
  enrolled: boolean;
  blocked: boolean[];
  roles: {
    governance: string;
    responder: string | null;
    blacklist: string;
    recovery: string;
    dispute: string;
  };
};
export type WalletRead = {
  chain_id: string;
  contract: string;
  controller: string;
  chain_time: string;
  height: string;
  wallet_security: WalletSecurity;
  guard: Guard;
  token_info: {
    name: string;
    symbol: string;
    decimals: number;
    total_supply: string;
  };
  balance: { balance: string };
};
export type Recovery = {
  nonce: number;
  token: string;
  source: string;
  destination: string;
  amount: string;
  evidence_hash: string;
  initiator: string;
  proposed_at: number;
  executable_at: number;
  authority_epoch: number;
  accepted: boolean;
  revoked: boolean;
  objected: boolean;
  objection_resolved: boolean;
  objection_resolution_hash: string | null;
  vetoed: boolean;
  cancellation_requested: boolean;
  cancellation_epoch: number | null;
  completed: boolean;
  cancelled: boolean;
  replaced_by: number | null;
};
export type RecoveryRead = {
  chain_id: string;
  contract: string;
  chain_time: string;
  height: string;
  recovery: Recovery;
};
export type TokenIdentity = { address: string; code_id: string };
export type ChainConfig = {
  chainId: string;
  controller: string;
  rpcUrl: string;
  abiSha: string;
  tokens: TokenIdentity[];
  gasPrice?: string;
  gasAdjustment: number;
};
export type Execute =
  | { set_wallet_policy: { policy: Policy } }
  | { rebase_protection: Record<string, never> }
  | { lock_wallet: Record<string, never> }
  | { request_unlock: Record<string, never> }
  | { execute_wallet_change: { nonce: number } }
  | { cancel_wallet_change: Record<string, never> }
  | { accept_recovery: { nonce: number } }
  | { revoke_recovery_acceptance: { nonce: number } }
  | { object_recovery: { nonce: number } };
export type Action =
  | "set_wallet_policy"
  | "rebase_protection"
  | "lock_wallet"
  | "request_unlock"
  | "execute_wallet_change"
  | "cancel_wallet_change"
  | "accept_recovery"
  | "revoke_recovery_acceptance"
  | "object_recovery";
export type Intent = {
  config: ChainConfig;
  token: TokenIdentity;
  signer: string;
  action: Action;
  msg: Execute;
  before: unknown;
  after: unknown;
  consequences: string;
  wallet: WalletRead;
  recovery?: RecoveryRead;
};
const U128 = (1n << 128n) - 1n;
export function uint(value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0)
    throw new Error(
      "An on-chain integer cannot be represented exactly. This action is unavailable.",
    );
  return value;
}
export function nonce(value: string): number {
  if (
    !/^(0|[1-9][0-9]*)$/.test(value) ||
    BigInt(value) > BigInt(Number.MAX_SAFE_INTEGER)
  )
    throw new Error("Enter an exact, safely supported unsigned case nonce.");
  return uint(Number(value));
}
export function units(value: unknown): string {
  if (
    typeof value !== "string" ||
    !/^(0|[1-9][0-9]*)$/.test(value) ||
    BigInt(value) > U128
  )
    throw new Error("An on-chain amount is invalid. No value was assumed.");
  return value;
}
function requireTrue(condition: unknown): asserts condition {
  if (!condition)
    throw new Error(
      "The chain returned an unsupported or mismatched response. Actions are unavailable.",
    );
}
function exactNumbers(value: unknown) {
  if (typeof value === "number") uint(value);
  else if (Array.isArray(value)) value.forEach(exactNumbers);
  else if (value && typeof value === "object")
    Object.values(value).forEach(exactNumbers);
}
function https(value: unknown): string {
  requireTrue(typeof value === "string");
  const url = new URL(value);
  requireTrue(
    url.protocol === "https:" && !url.username && !url.password && !url.hash,
  );
  return url.href;
}
export function chainConfig(chain: ChainStatus | undefined): ChainConfig {
  requireTrue(chain?.status === "ready" && chain.chain_id === "columbus-5");
  requireTrue(chain.abi_sha === SUPPORTED_ABI_SHA);
  requireTrue(
    typeof chain.controller === "string" &&
      chain.controller.startsWith("terra1"),
  );
  requireTrue(Array.isArray(chain.contracts) && chain.contracts.length > 0);
  const tokens = chain.contracts.map((raw) => {
    const token = raw as { address: unknown; code_id: unknown };
    requireTrue(
      token &&
        typeof token.address === "string" &&
        token.address.startsWith("terra1"),
    );
    const code =
      typeof token.code_id === "number"
        ? String(uint(token.code_id))
        : token.code_id;
    requireTrue(
      typeof code === "string" &&
        /^[1-9][0-9]*$/.test(code) &&
        BigInt(code) <= BigInt(Number.MAX_SAFE_INTEGER),
    );
    return { address: token.address, code_id: code };
  });
  const adjustment = chain.gas_adjustment ?? 1.4; // Pinned CosmJS client's default, disclosed in the review.
  requireTrue(
    typeof adjustment === "number" &&
      Number.isFinite(adjustment) &&
      adjustment >= 1 &&
      adjustment <= 10,
  );
  return {
    chainId: chain.chain_id,
    controller: chain.controller,
    rpcUrl: https(chain.rpc_url),
    abiSha: chain.abi_sha,
    tokens,
    gasPrice:
      typeof chain.gas_price === "string" && chain.gas_price.length
        ? chain.gas_price
        : undefined,
    gasAdjustment: adjustment,
  };
}
export function validatePolicy(p: Policy) {
  requireTrue(p && typeof p.enabled === "boolean");
  requireTrue(
    uint(p.limit_bps) <= 10000 &&
      uint(p.relaxation_delay) >= 86400 &&
      p.relaxation_delay <= 31536000 &&
      uint(p.unlock_delay) >= 172800 &&
      p.unlock_delay <= 31536000,
  );
  return p;
}
function assignment(a: ChainAssignment) {
  requireTrue(
    a &&
      typeof a.protocol === "boolean" &&
      typeof a.exempt === "boolean" &&
      typeof a.allow_lock === "boolean" &&
      typeof a.evidence_hash === "string",
  );
}
function timerFields(value: {
  nonce: number;
  proposed_at: number;
  executable_at: number;
  initiator: string;
}) {
  uint(value.nonce);
  uint(value.proposed_at);
  uint(value.executable_at);
  requireTrue(
    typeof value.initiator === "string" &&
      value.executable_at >= value.proposed_at &&
      value.executable_at <= 8640000000000,
  );
}
function times(
  value: {
    chain_time: string;
    height: string;
    chain_id: string;
    contract: string;
  },
  config: ChainConfig,
  token: string,
) {
  requireTrue(
    value &&
      value.chain_id === config.chainId &&
      value.contract === token &&
      typeof value.height === "string" &&
      /^\d+$/.test(value.height) &&
      typeof value.chain_time === "string" &&
      Number.isFinite(Date.parse(value.chain_time)),
  );
}
export function validateWallet(
  value: WalletRead,
  config: ChainConfig,
  token: string,
  wallet: string,
): WalletRead {
  exactNumbers(value);
  times(value, config, token);
  const w = value.wallet_security,
    g = value.guard;
  requireTrue(
    value.controller === config.controller &&
      w?.wallet === wallet &&
      typeof w.state?.locked === "boolean",
  );
  requireTrue(typeof w.initialized === "boolean");
  validatePolicy(w.state.policy);
  assignment(w.assignment);
  uint(g?.epoch);
  uint(g?.authority_epoch);
  units(w.state.protected_balance);
  units(w.reserved);
  units(w.rolling_spent);
  units(value.balance?.balance);
  requireTrue(Array.isArray(w.state.buckets));
  w.state.buckets.forEach((b) => {
    uint(b.hour);
    units(b.amount);
  });
  requireTrue(
    g?.interface_version === 1 &&
      typeof g.paused === "boolean" &&
      typeof g.enrolled === "boolean" &&
      Array.isArray(g.blocked) &&
      g.blocked.length === 1 &&
      typeof g.blocked[0] === "boolean" &&
      typeof g.roles?.governance === "string",
  );
  if (w.pending) {
    const p = w.pending;
    timerFields(p);
    requireTrue(
      typeof p.initiator === "string" && p.executable_at >= p.proposed_at,
    );
    if (p.change !== "unlock") {
      requireTrue(
        typeof p.change === "object" &&
          p.change !== null &&
          Object.keys(p.change).length === 1,
      );
      if ("policy" in p.change) validatePolicy(p.change.policy);
      else {
        requireTrue("rebase" in p.change);
        units(p.change.rebase);
      }
    }
  }
  if (w.pending_assignment) {
    timerFields(w.pending_assignment);
    uint(w.pending_assignment.authority_epoch);
    assignment(w.pending_assignment.assignment);
  }
  requireTrue(
    typeof value.token_info?.name === "string" &&
      typeof value.token_info.symbol === "string" &&
      uint(value.token_info.decimals) <= 18,
  );
  units(value.token_info.total_supply);
  return value;
}
export function validateRecovery(
  value: RecoveryRead,
  config: ChainConfig,
  token: string,
  expectedNonce: number,
): RecoveryRead {
  exactNumbers(value);
  times(value, config, token);
  const r = value.recovery;
  requireTrue(
    r &&
      r.token === token &&
      r.nonce === expectedNonce &&
      typeof r.source === "string" &&
      typeof r.destination === "string" &&
      typeof r.evidence_hash === "string" &&
      /^[a-f0-9]{64}$/.test(r.evidence_hash) &&
      r.executable_at >= r.proposed_at,
  );
  timerFields(r);
  uint(r.authority_epoch);
  if (r.cancellation_epoch !== null) uint(r.cancellation_epoch);
  if (r.replaced_by !== null) uint(r.replaced_by);
  units(r.amount);
  for (const field of [
    "accepted",
    "revoked",
    "objected",
    "objection_resolved",
    "vetoed",
    "cancellation_requested",
    "completed",
    "cancelled",
  ] as const)
    requireTrue(typeof r[field] === "boolean");
  return value;
}
export function weakening(old: Policy, next: Policy) {
  return (
    (!next.enabled && old.enabled) ||
    next.limit_bps > old.limit_bps ||
    next.relaxation_delay < old.relaxation_delay ||
    next.unlock_delay < old.unlock_delay
  );
}
export function fingerprint(value: WalletRead | RecoveryRead): string {
  // Time/height advance normally. Every other queried field must remain exactly reviewed.
  const { chain_time: _time, height: _height, ...data } = value;
  return JSON.stringify(data);
}
export function makeIntent(
  config: ChainConfig,
  w: WalletRead,
  signer: string,
  action: Action,
  next?: Policy,
  recovery?: RecoveryRead,
): Intent {
  const token = config.tokens.find((t) => t.address === w.contract);
  requireTrue(token && signer === w.wallet_security.wallet);
  const state = w.wallet_security.state,
    pending = w.wallet_security.pending;
  let msg: Execute;
  let before: unknown = { policy: state.policy, locked: state.locked, pending };
  let after: unknown;
  let consequences: string;
  switch (action) {
    case "set_wallet_policy": {
      requireTrue(next);
      validatePolicy(next);
      msg = { set_wallet_policy: { policy: next } };
      const weak = weakening(state.policy, next);
      after = weak
        ? { effective_policy: state.policy, new_pending_policy: next }
        : { effective_policy: next, pending: null };
      consequences = weak
        ? `Any weakening delays the entire payload under the OLD ${state.policy.relaxation_delay}s relaxation delay. Existing policy stays effective. Replacing a pending change restarts the full delay. Explicit execution is required after the chain deadline.`
        : "This policy applies immediately and invalidates all pending wallet changes, including unlock. Spending history is preserved.";
      break;
    }
    case "rebase_protection":
      msg = { rebase_protection: {} };
      after = {
        pending_basis:
          "Balance captured by the contract at transaction execution",
        queried_balance_reference: w.balance.balance,
        effective_basis: state.protected_balance,
      };
      consequences = `Schedules the balance captured at transaction execution as a new protection basis (it can differ from this queried balance) under the OLD ${state.policy.relaxation_delay}s relaxation delay. Replaces any pending change. Explicit execution required; spending history is preserved.`;
      break;
    case "lock_wallet":
      requireTrue(
        !w.wallet_security.assignment.protocol ||
          w.wallet_security.assignment.allow_lock,
      );
      msg = { lock_wallet: {} };
      after = { locked: true, pending: null };
      consequences =
        "Immediately blocks ordinary outgoing token movements and cancels any pending change/unlock. Relocking preserves spending history and recovery reservations. Adjudicated recovery is a separate authorized path.";
      break;
    case "request_unlock":
      requireTrue(state.locked);
      msg = { request_unlock: {} };
      after = { locked: true, pending: "unlock" };
      consequences = `Lock stays effective during the OLD ${state.policy.unlock_delay}s unlock delay. Replaces any pending change and restarts the full delay. Explicit execution is required after expiry.`;
      break;
    case "execute_wallet_change":
      requireTrue(
        pending && pending.executable_at * 1000 <= Date.parse(w.chain_time),
      );
      msg = { execute_wallet_change: { nonce: pending.nonce } };
      after = { apply_exact_pending: pending.change, pending: null };
      consequences =
        "Applies only this exact pending nonce after the contract confirms its chain deadline. The countdown alone never changes state. An intervening change can invalidate this transaction.";
      break;
    case "cancel_wallet_change":
      requireTrue(pending);
      msg = { cancel_wallet_change: {} };
      after = { policy: state.policy, locked: state.locked, pending: null };
      consequences =
        "Cancels the current pending wallet change. Effective policy and current lock stay unchanged. Spending history and recovery reservations remain.";
      break;
    default: {
      requireTrue(recovery && recovery.contract === w.contract);
      const r = recovery.recovery;
      requireTrue(!r.completed && !r.cancelled && r.replaced_by === null);
      before = r;
      if (action === "accept_recovery") {
        requireTrue(
          signer === r.destination &&
            !r.revoked &&
            !r.accepted &&
            w.guard.authority_epoch === r.authority_epoch &&
            !w.guard.blocked[0],
        );
        msg = { accept_recovery: { nonce: r.nonce } };
        after = { ...r, accepted: true };
        consequences =
          "Accepts ONLY the exact stored chain/token/source/destination/amount/evidence/nonce shown here. This does not execute recovery. Separate recovery authority, contest deadline, epoch and dispute checks still apply.";
      } else if (action === "revoke_recovery_acceptance") {
        requireTrue(signer === r.destination && !r.revoked);
        msg = { revoke_recovery_acceptance: { nonce: r.nonce } };
        after = { ...r, accepted: false, revoked: true };
        consequences =
          "Permanently invalidates acceptance for this nonce. Reacceptance requires a new immutable proposal and full contest delay. Revocation does not release the source reservation or remove containment.";
      } else {
        requireTrue(
          action === "object_recovery" && signer === r.source && !r.objected,
        );
        msg = { object_recovery: { nonce: r.nonce } };
        after = { ...r, objected: true };
        consequences =
          "Records the source objection. Unresolved objection blocks recovery execution pending independent dispute resolution. It cannot cancel the case, release reservations, change destination or reset the timer. Repeated objections give no new authority.";
      }
    }
  }
  if (
    !w.wallet_security.initialized &&
    ["set_wallet_policy", "lock_wallet", "rebase_protection"].includes(action)
  ) {
    consequences +=
      " This explicit owner action also initializes the opening protection basis using the balance at execution, which may differ from this lazy query snapshot.";
  }
  return {
    config,
    token,
    signer,
    action,
    msg,
    before,
    after,
    consequences,
    wallet: w,
    recovery,
  };
}
export function budget(w: WalletRead): string {
  const cap =
    (BigInt(w.wallet_security.state.protected_balance) *
      BigInt(w.wallet_security.state.policy.limit_bps)) /
    10000n;
  const remaining = cap - BigInt(w.wallet_security.rolling_spent);
  return (remaining > 0n ? remaining : 0n).toString();
}
