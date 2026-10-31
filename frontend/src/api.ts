export type Wallet = { address: string; verified_at: string };
export type Role = "guardian" | "recovery" | "notification";
export type Assignment = {
  id: string;
  owner_wallet: string;
  candidate_wallet: string;
  role: Role;
  status: "awaiting_consent" | "pending" | "active" | "cancelled" | "removed";
  proposed_at: string;
  executable_at: string;
  accepted_at: string | null;
  delay_seconds: number;
  removal_at?: string | null;
};
export type ContactStatus = {
  id: string;
  kind: "email" | "telegram";
  status: string;
  removal_at: string | null;
  activation_at?: string | null;
};
export type ChainStatus = {
  status: "unavailable" | "ready";
  chain_id: string;
  reason: string;
  contracts: unknown[];
};
export type Me = {
  authenticated: boolean;
  csrf_token?: string;
  profile_id?: string;
  anchor_wallet?: string;
  server_time?: string;
  wallets: Wallet[];
  assignments: Assignment[];
  contacts: ContactStatus[];
  chain: ChainStatus;
};
export type Challenge = {
  id: string;
  message: string;
  expires_at: string;
  chain_id: string;
};
export type ServiceStatus = {
  source_sha: string;
  chain: ChainStatus;
  notifications: unknown;
  worker: unknown;
};

let csrf = "";
export function setCsrf(value: string) {
  csrf = value;
}
export class ApiError extends Error {
  constructor(public status: number) {
    // Never echo server bodies: errors can contain private destinations or provider details.
    super(
      status === 401
        ? "Your session expired. Sign in again."
        : status === 403
          ? "This request was refused. Refresh your session and try again."
          : status === 429
            ? "Too many requests. Wait before trying again."
            : status === 503
              ? "This service is unavailable. No delivery or change is confirmed."
              : "The request could not be confirmed. Refresh before retrying.",
    );
  }
}
export async function api<T>(path: string, body?: unknown): Promise<T> {
  let response: Response;
  try {
    response = await fetch("/api/v1" + path, {
      method: body === undefined ? "GET" : "POST",
      credentials: "same-origin",
      cache: "no-store",
      headers:
        body === undefined
          ? {}
          : { "Content-Type": "application/json", "X-CSRF-Token": csrf },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(20_000),
    });
  } catch {
    throw new Error(
      "Cannot reach the service. Your last snapshot may be stale; refresh before making changes.",
    );
  }
  if (!response.ok) throw new ApiError(response.status);
  if (response.status === 204) return undefined as T;
  try {
    return (await response.json()) as T;
  } catch {
    throw new Error(
      "The service returned an unreadable response. Refresh before making changes.",
    );
  }
}
export function assertMe(value: Me): Me {
  if (
    !value ||
    typeof value.authenticated !== "boolean" ||
    !Array.isArray(value.wallets) ||
    !Array.isArray(value.assignments) ||
    !Array.isArray(value.contacts) ||
    !value.chain ||
    typeof value.chain.chain_id !== "string" ||
    !["ready", "unavailable"].includes(value.chain.status) ||
    (value.authenticated &&
      (!value.csrf_token || !value.anchor_wallet || !value.profile_id))
  ) {
    throw new Error(
      "The service returned an unsupported session format. Actions are unavailable.",
    );
  }
  return value;
}
