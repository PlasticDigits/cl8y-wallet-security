import AxeBuilder from "@axe-core/playwright";
import { test, expect } from "@playwright/test";
import type { Page } from "@playwright/test";
import type { Me, Assignment } from "../src/api";
import { formatUnits } from "../src/format";

// Synthetic addresses and provider/API doubles only. This is not a live wallet signing test.
const owner = "terra1" + "a".repeat(38);
const candidate = "terra1" + "b".repeat(38);
const epoch = "2030-01-01T00:00:00Z";
const tomorrow = "2030-01-02T00:00:00Z";
function role(status: Assignment["status"] = "awaiting_consent"): Assignment {
  return {
    id: "test-proposal",
    owner_wallet: owner,
    candidate_wallet: candidate,
    role: "guardian",
    status,
    proposed_at: epoch,
    executable_at: tomorrow,
    delay_seconds: 86400,
    accepted_at: status === "awaiting_consent" ? null : epoch,
    removal_at: null,
  };
}
async function harness(
  page: Page,
  authenticated = false,
  assignments: Assignment[] = [],
  provider = true,
) {
  const me: Me = {
    authenticated,
    csrf_token: "test-csrf",
    profile_id: authenticated ? "test-profile" : undefined,
    anchor_wallet: authenticated ? owner : undefined,
    server_time: epoch,
    wallets: authenticated ? [{ address: owner, verified_at: epoch }] : [],
    assignments,
    contacts: [],
    chain: {
      status: "unavailable",
      chain_id: "columbus-5",
      reason: "Verified deployments unavailable",
      contracts: [],
    },
  };
  const calls: {
    path: string;
    body: Record<string, unknown>;
    csrf: string | undefined;
  }[] = [];
  let challenge: Record<string, string> = {};
  let contactMode: "disabled" | "queued" | "bad-url" | "ready" = "disabled";
  let expired = false;
  if (provider)
    await page.addInitScript(
      ({ owner }) => {
        const state = window as unknown as {
          testAccount: string;
          signed: unknown[];
          keplr: unknown;
          station: unknown;
        };
        state.testAccount = owner;
        state.signed = [];
        const wallet = {
          enable: async () => {},
          getKey: async () => ({
            bech32Address: state.testAccount,
            algo: "secp256k1",
            pubKey: new Uint8Array(33),
          }),
          signArbitrary: async (
            chain: string,
            address: string,
            message: string,
          ) => {
            state.signed.push({ chain, address, message });
            return {
              pub_key: {
                type: "tendermint/PubKeySecp256k1",
                value: btoa(String.fromCharCode(2) + "k".repeat(32)),
              },
              signature: btoa("s".repeat(64)),
            };
          },
        };
        state.keplr = wallet;
        state.station = { keplr: wallet };
      },
      { owner },
    );
  await page.route("**/api/v1/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname.replace("/api/v1", "");
    const body = request.postDataJSON() ?? {};
    if (request.method() === "POST")
      calls.push({ path, body, csrf: request.headers()["x-csrf-token"] });
    let result: unknown = {};
    if (path === "/me") result = me;
    else if (path === "/status")
      result = {
        source_sha: "test",
        chain: me.chain,
        worker: null,
        notifications: {
          delivery_enabled: contactMode !== "disabled",
          email_ready: contactMode !== "disabled",
          telegram_ready: contactMode !== "disabled",
        },
      };
    else if (path === "/auth/challenge") {
      challenge = {
        id: "test-challenge",
        chain_id: me.chain.chain_id,
        expires_at: expired ? "2029-01-01T00:00:00Z" : tomorrow,
        message: `test nonce, purpose ${body.purpose}, signer ${body.address}, origin http://127.0.0.1:4177`,
      };
      result = challenge;
    } else if (path === "/auth/verify") {
      if (challenge.message.includes("purpose login,")) {
        me.authenticated = true;
        me.profile_id = "test-profile";
        me.anchor_wallet = owner;
        me.wallets = [{ address: owner, verified_at: epoch }];
        result = { csrf_token: "test-csrf" };
      } else {
        if (challenge.message.includes("purpose add_wallet,"))
          me.wallets.push({ address: candidate, verified_at: epoch });
        else if (me.assignments[0]) {
          me.assignments[0].accepted_at = epoch;
          me.assignments[0].status = "pending";
        }
        result = { verified: true };
      }
    } else if (path === "/assignments") {
      me.assignments.push(role());
      result = { id: "test-proposal" };
    } else if (path.endsWith("/cancel")) {
      const item = me.assignments[0]!;
      if (item.status === "active") item.removal_at = tomorrow;
      else item.status = "cancelled";
      result = { ok: true };
    } else if (path.startsWith("/contacts/")) {
      if (contactMode === "disabled")
        return route.fulfill({
          status: 503,
          json: { error: "private fixture must never echo" },
        });
      if (path === "/contacts/email")
        result = {
          id: "test-contact",
          queued: true,
          sent: false,
          status: "unverified",
        };
      if (path === "/contacts/telegram")
        result = {
          id: "test-contact",
          pairing_url:
            contactMode === "bad-url"
              ? "javascript:alert(1)"
              : "https://t.me/test_configured_bot?start=test-token",
          status: "unverified",
        };
      if (path.endsWith("/verify") || path.endsWith("/confirm")) {
        me.contacts = [
          {
            id: "test-contact",
            kind: path.includes("telegram") ? "telegram" : "email",
            status: "pending",
            activation_at: tomorrow,
            removal_at: null,
          },
        ];
        result = { verified: true, activation_at: tomorrow, status: "pending" };
      }
    } else if (path === "/auth/logout") {
      me.authenticated = false;
      me.wallets = [];
      me.assignments = [];
    }
    await route.fulfill({ json: result });
  });
  await page.goto("/");
  await expect(
    page.getByRole("button", { name: "Connect selected wallet" }),
  ).toBeEnabled();
  return {
    me,
    calls,
    expire: () => {
      expired = true;
    },
    contacts: (mode: typeof contactMode) => {
      contactMode = mode;
    },
  };
}
async function selectCandidate(page: Page) {
  await page.evaluate((candidate) => {
    (window as unknown as { testAccount: string }).testAccount = candidate;
    window.dispatchEvent(new Event("keplr_keystorechange"));
  }, candidate);
  await page.getByRole("button", { name: "Connect selected wallet" }).click();
}

test("rendered login, independently add wallet, propose, candidate consent and cancel survive refresh", async ({
  page,
}) => {
  const h = await harness(page);
  await expect(
    page.getByRole("heading", { name: "On-chain protection" }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Connect selected wallet" }).click();
  await expect(
    page.getByRole("button", { name: "Review sign-in challenge" }),
  ).toBeVisible();
  expect(h.calls.filter((c) => c.path === "/auth/verify")).toHaveLength(0);
  await page.getByRole("button", { name: "Review sign-in challenge" }).click();
  await expect(
    page.getByRole("heading", { name: "Sign in to this profile" }),
  ).toBeFocused();
  await page.getByRole("button", { name: "Sign proof", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "Verified profile" }),
  ).toBeVisible();
  await selectCandidate(page);
  await page.getByRole("button", { name: "Review add-wallet proof" }).click();
  await page.getByRole("button", { name: "Sign proof", exact: true }).click();
  await expect(page.locator("#portfolio .wallets li")).toHaveCount(2);
  await page.getByLabel("Candidate Terra Classic address").fill(candidate);
  await page.getByRole("button", { name: "Review role proposal" }).click();
  expect(h.calls.filter((c) => c.path === "/assignments")).toHaveLength(0);
  await page.getByRole("button", { name: "Confirm profile change" }).click();
  await expect(page.locator(".assignment")).toContainText("awaiting consent");
  await page.getByRole("button", { name: "Review candidate consent" }).click();
  await expect(page.locator(".review")).toContainText("Candidate role");
  await page.getByRole("button", { name: "Sign proof", exact: true }).click();
  await expect(page.locator(".assignment")).toContainText("pending");
  await page.reload();
  await expect(page.locator(".assignment")).toContainText("pending");
  await expect(page.locator(".assignment")).toContainText(
    "2030-01-01 00:00:00 UTC",
  );
  await page.getByRole("button", { name: "Review cancellation" }).click();
  await page.getByRole("button", { name: "Confirm profile change" }).click();
  await expect(page.locator(".assignment")).toContainText("cancelled");
  expect(h.calls.filter((c) => c.path === "/auth/verify")).toHaveLength(3);
  expect(
    h.calls
      .filter((c) => c.path !== "/auth/challenge" || c.body.purpose !== "login")
      .every((c) => c.csrf === "test-csrf"),
  ).toBe(true);
});

test("wrong candidate, account changes and expired proof never submit a signature", async ({
  page,
}) => {
  const h = await harness(page, true, [role()]);
  await page.getByRole("button", { name: "Connect selected wallet" }).click();
  await page.getByRole("button", { name: "Review candidate consent" }).click();
  await expect(page.locator("#feedback")).toContainText(
    "owner cannot sign consent",
  );
  expect(h.calls.filter((c) => c.path === "/auth/challenge")).toHaveLength(0);
  await selectCandidate(page);
  await page.getByRole("button", { name: "Review candidate consent" }).click();
  await page.evaluate(() =>
    window.dispatchEvent(new Event("keplr_keystorechange")),
  );
  await expect(
    page.getByRole("button", { name: "Sign proof", exact: true }),
  ).toHaveCount(0);
  h.expire();
  await page.getByRole("button", { name: "Connect selected wallet" }).click();
  await page.getByRole("button", { name: "Review candidate consent" }).click();
  await page.getByRole("button", { name: "Sign proof", exact: true }).click();
  await expect(page.locator("#feedback")).toContainText("challenge expired");
  expect(h.calls.filter((c) => c.path === "/auth/verify")).toHaveLength(0);
});

test("server active role remains active during delayed removal and local deadline cannot promote state", async ({
  page,
}) => {
  const h = await harness(page, true, [role("active")]);
  await page.getByRole("button", { name: "Review delayed removal" }).click();
  await expect(page.locator(".review")).toContainText(
    "active role remains effective",
  );
  await page.getByRole("button", { name: "Confirm profile change" }).click();
  await expect(page.locator(".assignment")).toContainText(
    "Active · removal scheduled",
  );
  await page.reload();
  await expect(page.locator(".assignment")).toContainText(
    "Active · removal scheduled",
  );
  h.me.server_time = "2030-01-03T00:00:00Z";
  await page.getByRole("button", { name: "Refresh status" }).click();
  await expect(page.locator(".assignment")).toContainText("Deadline reached");
  await expect(page.locator(".assignment")).toContainText(
    "Active · removal scheduled",
  );
});

test("contact readiness, queued email, Telegram URL checks and delayed verification are honest", async ({
  page,
}) => {
  const h = await harness(page, true);
  await expect(page.locator("#contacts")).toContainText(
    "Notification delivery is disabled",
  );
  await page
    .getByLabel("Email address", { exact: true })
    .fill("test@example.invalid");
  await page
    .getByRole("button", { name: "Request email verification" })
    .click();
  await expect(page.locator("#feedback")).toContainText(
    "No delivery or change is confirmed",
  );
  await expect(page.locator("#feedback")).not.toContainText("private fixture");
  await expect(page.getByLabel("Email address", { exact: true })).toHaveValue(
    "",
  );
  h.contacts("queued");
  await page
    .getByLabel("Email address", { exact: true })
    .fill("test@example.invalid");
  await page
    .getByRole("button", { name: "Request email verification" })
    .click();
  await expect(page.locator("#feedback")).toContainText(
    "queued. Delivery is not yet confirmed",
  );
  await page.getByLabel("One-use verification token").fill("synthetic-token");
  await page.getByRole("button", { name: "Verify email token" }).click();
  await expect(page.locator(".contacts")).toContainText(
    "Replacement contact pending",
  );
  await expect(page.getByLabel("One-use verification token")).toHaveValue("");
  h.contacts("bad-url");
  await page.getByRole("button", { name: "Request Telegram pairing" }).click();
  await expect(
    page.getByRole("link", { name: "Open Telegram bot pairing" }),
  ).toHaveCount(0);
  h.contacts("ready");
  await page.getByRole("button", { name: "Request Telegram pairing" }).click();
  await expect(
    page.getByRole("link", { name: "Open Telegram bot pairing" }),
  ).toHaveAttribute(
    "href",
    "https://t.me/test_configured_bot?start=test-token",
  );
  await page
    .getByLabel("Telegram confirmation code")
    .fill("synthetic-confirmation");
  await page.getByRole("button", { name: "Confirm Telegram code" }).click();
  await expect(page.locator(".contacts")).toContainText("telegram");
  expect(
    await page.evaluate(() => localStorage.length + sessionStorage.length),
  ).toBe(0);
});

test("mobile layout, missing provider, Station bridge and escaped service text", async ({
  page,
}) => {
  await page.setViewportSize({ width: 375, height: 812 });
  const h = await harness(page, false, [], false);
  await page.getByRole("button", { name: "Connect selected wallet" }).click();
  await expect(page.locator("#feedback")).toContainText(
    "provider is unavailable",
  );
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
  ).toBe(true);
  const accessibility = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21aa"])
    .analyze();
  expect(
    accessibility.violations.map((v) => ({
      id: v.id,
      targets: v.nodes.map((n) => n.target),
    })),
  ).toEqual([]);
  if (process.env.PORTAL_SCREENSHOT)
    await page.screenshot({
      path: process.env.PORTAL_SCREENSHOT,
      fullPage: true,
    });
  h.me.chain.reason = "<img src=x onerror=alert(1)>";
  await page.getByRole("button", { name: "Refresh status" }).click();
  await expect(page.locator(".chain img")).toHaveCount(0);
  await expect(page.locator(".chain")).toContainText("<img");
  await page.evaluate((owner) => {
    window.station = {
      keplr: {
        enable: async () => {},
        getKey: async () => ({
          bech32Address: owner,
          algo: "secp256k1",
          pubKey: new Uint8Array(33),
        }),
        signArbitrary: async () => {
          throw new Error("not used");
        },
      },
    };
  }, owner);
  await page.getByLabel("Injected wallet").selectOption("station");
  await page.getByRole("button", { name: "Connect selected wallet" }).click();
  await expect(
    page.getByRole("button", { name: "Review sign-in challenge" }),
  ).toBeVisible();
  await expect(
    page.locator("form input:not([id]), form select:not([id])"),
  ).toHaveCount(0);
  await expect(page.locator("#feedback")).toHaveAttribute(
    "aria-live",
    "polite",
  );
});

test("base-unit amounts preserve all digits without floating point loss", () => {
  expect(formatUnits("340282366920938463463374607431768211455", 6)).toBe(
    "340282366920938463463374607431768.211455",
  );
  expect(formatUnits("000001", 6)).toBe("0.000001");
  expect(formatUnits("1000000", 6)).toBe("1");
  expect(() => formatUnits("1e6", 6)).toThrow();
});
