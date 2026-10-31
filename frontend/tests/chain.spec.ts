import { test, expect } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import type { OfflineAminoSigner, StdFee, StdSignDoc } from "@cosmjs/amino";
import {
  chainConfig,
  makeIntent,
  nonce,
  SUPPORTED_ABI_SHA,
  validateRecovery,
  validateWallet,
} from "../src/chain";
import type { RecoveryRead, WalletRead } from "../src/chain";
import type { Me } from "../src/api";
import { prepareTransaction } from "../src/transactions";
import type { ClientFactory, TxClient } from "../src/transactions";
import type { Connection } from "../src/wallet";

// All identities, RPCs, balances, signatures and receipts below are synthetic doubles.
const owner = "terra1" + "a".repeat(38),
  destination = "terra1" + "b".repeat(38);
const token = "terra1" + "c".repeat(38),
  controller = "terra1" + "d".repeat(38);
const chain = {
  status: "ready" as const,
  chain_id: "columbus-5",
  reason: "Synthetic verified test config",
  contracts: [{ address: token, code_id: 17 }],
  controller,
  abi_sha: SUPPORTED_ABI_SHA,
  rpc_url: "https://rpc.example.invalid/",
  lcd_url: "https://lcd.example.invalid/",
  gas_price: "0.1utest" as string | null,
};
function walletRead(address = owner): WalletRead {
  return {
    chain_id: "columbus-5",
    contract: token,
    controller,
    chain_time: "2030-01-01T00:00:00Z",
    height: "1234",
    wallet_security: {
      wallet: address,
      initialized: false,
      state: {
        policy: {
          enabled: true,
          limit_bps: 1000,
          relaxation_delay: 86400,
          unlock_delay: 172800,
        },
        protected_balance: "9007199254740993123456",
        locked: true,
        buckets: [],
      },
      pending: {
        nonce: 42,
        proposed_at: 1893455990,
        executable_at: 1893456001,
        initiator: address,
        change: "unlock",
      },
      assignment: {
        protocol: false,
        exempt: false,
        allow_lock: false,
        evidence_hash: "",
      },
      pending_assignment: null,
      reserved: "1000000",
      rolling_spent: "2000000",
    },
    guard: {
      interface_version: 1,
      epoch: 1,
      authority_epoch: 2,
      paused: true,
      enrolled: true,
      blocked: [false],
      roles: {
        governance: controller,
        responder: null,
        blacklist: controller,
        recovery: controller,
        dispute: controller,
      },
    },
    token_info: {
      name: "Synthetic Token",
      symbol: "TEST",
      decimals: 6,
      total_supply: "9007199254740993123456",
    },
    balance: { balance: "9007199254740993123456" },
  };
}
function recoveryRead(): RecoveryRead {
  return {
    chain_id: "columbus-5",
    contract: token,
    chain_time: "2030-01-01T00:00:00Z",
    height: "1234",
    recovery: {
      nonce: 7,
      token,
      source: owner,
      destination,
      amount: "1000000",
      evidence_hash: "e".repeat(64),
      initiator: controller,
      proposed_at: 1893455990,
      executable_at: 1896047990,
      authority_epoch: 2,
      accepted: false,
      revoked: false,
      objected: false,
      objection_resolved: false,
      objection_resolution_hash: null,
      vetoed: false,
      cancellation_requested: false,
      cancellation_epoch: null,
      completed: false,
      cancelled: false,
      replaced_by: null,
    },
  };
}

test("authoritative chain UI shows exact amounts, chain timers, recovery authority and missing-fee gate", async ({
  page,
}) => {
  const configured: typeof chain = { ...chain, gas_price: null };
  const me: Me = {
    authenticated: true,
    csrf_token: "test-csrf",
    profile_id: "test-profile",
    anchor_wallet: owner,
    server_time: "2030-01-01T00:00:00Z",
    wallets: [
      { address: owner, verified_at: "2030-01-01T00:00:00Z" },
      { address: destination, verified_at: "2030-01-01T00:00:00Z" },
    ],
    assignments: [],
    contacts: [],
    chain: configured,
  };
  let chainCalls = 0;
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path.endsWith("/me")) return route.fulfill({ json: me });
    if (path.endsWith("/status"))
      return route.fulfill({
        json: { notifications: { delivery_enabled: false }, chain: configured },
      });
    chainCalls++;
    if (path.includes("/chain/wallet/"))
      return route.fulfill({ json: walletRead(path.split("/").pop()) });
    if (path.includes("/chain/recovery/"))
      return route.fulfill({ json: recoveryRead() });
    return route.fulfill({ status: 503, json: { error: "unavailable" } });
  });
  await page.goto("/");
  await page
    .getByRole("button", { name: "Load authoritative token / wallet state" })
    .click();
  await expect(page.locator(".chain-wallet")).toContainText(
    "9007199254740993.123456",
  );
  await expect(page.locator(".chain-wallet")).toContainText(
    "Lazy current balance; not yet persisted",
  );
  await expect(page.locator(".chain-wallet")).toContainText("Fleet paused");
  await expect(page.locator(".chain-wallet")).toContainText(
    "Operator gas price unavailable",
  );
  await expect(
    page.getByRole("button", { name: "Review pending execution" }),
  ).toBeDisabled();
  await expect(page.getByLabel("Limit in basis points")).toHaveValue("1000");
  await expect(
    page.getByRole("button", { name: "Simulate policy and review fee" }),
  ).toBeDisabled();
  await page.getByLabel("Recovery nonce for this token").fill("7");
  await page
    .getByRole("button", { name: "Load authoritative recovery case" })
    .click();
  await expect(page.locator("#onchain")).toContainText("1 TEST");
  await expect(page.locator("#onchain")).toContainText(
    "Acceptance is not execution",
  );
  await expect(
    page.getByRole("button", { name: "Review exact destination acceptance" }),
  ).toBeDisabled();
  await expect(page.locator("#onchain")).toContainText("e".repeat(64));
  await page.setViewportSize({ width: 375, height: 812 });
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
  ).toBe(true);
  const accessibility = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21aa"])
    .analyze();
  expect(accessibility.violations.map((v) => v.id)).toEqual([]);
  await page.getByRole("button", { name: "Refresh status" }).click();
  await expect(page.locator(".chain-wallet")).toHaveCount(0);
  const callsBefore = chainCalls;
  configured.abi_sha = "f".repeat(40);
  await page.getByRole("button", { name: "Refresh status" }).click();
  await expect(page.locator("#onchain")).toContainText(
    "Unsupported source pins remain gated",
  );
  await expect(
    page.getByRole("button", {
      name: "Load authoritative token / wallet state",
    }),
  ).toHaveCount(0);
  expect(chainCalls).toBe(callsBefore);
  // Exercise the actual lazy browser client; intercept its synthetic RPC before any network.
  configured.abi_sha = SUPPORTED_ABI_SHA;
  configured.gas_price = "0.1utest";
  let rpcCalls = 0;
  await page.route("https://rpc.example.invalid/**", (route) => {
    rpcCalls++;
    return route.abort("failed");
  });
  await page.evaluate((owner) => {
    window.keplr = {
      enable: async () => {},
      getKey: async () => ({
        bech32Address: owner,
        algo: "secp256k1",
        pubKey: new Uint8Array(33),
      }),
      signArbitrary: async () => {
        throw new Error("unused");
      },
      signAmino: async () => {
        throw new Error("must not sign after failed simulation");
      },
    };
  }, owner);
  await page.getByRole("button", { name: "Refresh status" }).click();
  await page.getByRole("button", { name: "Connect selected wallet" }).click();
  await page
    .getByRole("button", { name: "Load authoritative token / wallet state" })
    .click();
  await page
    .getByRole("button", { name: "Review relock and cancel pending" })
    .click();
  await expect(page.locator("#feedback")).toContainText(
    "No signature or broadcast was requested",
  );
  expect(rpcCalls).toBeGreaterThan(0);
  await expect(
    page.getByRole("button", {
      name: "Sign and broadcast reviewed transaction",
    }),
  ).toHaveCount(0);
});

test("policy old-delay semantics, exact nonce/recovery payload, stale epoch and unsafe integers", () => {
  const c = chainConfig(chain),
    w = validateWallet(walletRead(), c, token, owner);
  const next = {
    ...w.wallet_security.state.policy,
    enabled: false,
    relaxation_delay: 172800,
  };
  const weak = makeIntent(c, w, owner, "set_wallet_policy", next);
  expect(weak.msg).toEqual({ set_wallet_policy: { policy: next } });
  expect(weak.consequences).toContain("OLD 86400s");
  expect(weak.after).toEqual({
    effective_policy: w.wallet_security.state.policy,
    new_pending_policy: next,
  });
  const tighten = makeIntent(c, w, owner, "set_wallet_policy", {
    ...next,
    enabled: true,
    limit_bps: 500,
  });
  expect(tighten.consequences).toContain("applies immediately");
  expect(makeIntent(c, w, owner, "lock_wallet").msg).toEqual({
    lock_wallet: {},
  });
  expect(() => makeIntent(c, w, owner, "execute_wallet_change")).toThrow();
  w.chain_time = "2030-01-01T00:00:02Z";
  expect(makeIntent(c, w, owner, "execute_wallet_change").msg).toEqual({
    execute_wallet_change: { nonce: 42 },
  });
  const r = validateRecovery(recoveryRead(), c, token, 7);
  expect(() =>
    makeIntent(c, w, owner, "accept_recovery", undefined, r),
  ).toThrow();
  const destRead = walletRead(destination);
  expect(
    makeIntent(c, destRead, destination, "accept_recovery", undefined, r).msg,
  ).toEqual({ accept_recovery: { nonce: 7 } });
  expect(
    makeIntent(
      c,
      destRead,
      destination,
      "revoke_recovery_acceptance",
      undefined,
      r,
    ).consequences,
  ).toContain("Permanently invalidates");
  expect(makeIntent(c, w, owner, "object_recovery", undefined, r).msg).toEqual({
    object_recovery: { nonce: 7 },
  });
  r.recovery.authority_epoch = 1;
  expect(() =>
    makeIntent(c, destRead, destination, "accept_recovery", undefined, r),
  ).toThrow();
  expect(() => nonce("9007199254740993")).toThrow();
  const unsafe = walletRead();
  unsafe.wallet_security.pending!.nonce = JSON.parse("9007199254740993");
  expect(() => validateWallet(unsafe, c, token, owner)).toThrow();
});

function transactionDouble(
  modifyFee = false,
  code = 0,
  failSimulation = false,
) {
  let signatures = 0,
    broadcasts = 0;
  let offline: OfflineAminoSigner;
  const connection: Connection = {
    kind: "keplr",
    chainId: "columbus-5",
    address: owner,
    wallet: {
      enable: async () => {},
      getKey: async () => ({
        bech32Address: owner,
        algo: "secp256k1",
        pubKey: new Uint8Array(33),
      }),
      signArbitrary: async () => {
        throw new Error("unused");
      },
      signAmino: async (_chain, _address, document) => {
        signatures++;
        const signed = structuredClone(document);
        if (modifyFee) signed.fee = { ...signed.fee, gas: "999999" };
        return {
          signed,
          signature: {
            pub_key: {
              type: "tendermint/PubKeySecp256k1",
              value: "test-double",
            },
            signature: "test-double",
          },
        };
      },
    },
  };
  const factory: ClientFactory = async (_url, signer) => {
    offline = signer;
    return {
      getChainId: async () => "columbus-5",
      getContract: async () => ({ codeId: 17 }),
      queryContractSmart: async () => ({ controller }),
      simulate: async (_address, messages) => {
        expect(messages).toHaveLength(1);
        expect(messages[0]!.typeUrl).toBe(
          "/cosmwasm.wasm.v1.MsgExecuteContract",
        );
        if (failSimulation) throw new Error("synthetic unavailable");
        return 100000;
      },
      signAndBroadcast: async (
        sender: string,
        messages: { value: { msg: Uint8Array } }[],
        fee: StdFee,
      ) => {
        const doc: StdSignDoc = {
          chain_id: "columbus-5",
          account_number: "4",
          sequence: "5",
          memo: "",
          fee,
          msgs: [
            {
              type: "wasm/MsgExecuteContract",
              value: {
                sender,
                contract: token,
                msg: JSON.parse(
                  new TextDecoder().decode(messages[0]!.value.msg),
                ),
                funds: [],
              },
            },
          ],
        };
        await offline.signAmino(sender, doc);
        broadcasts++;
        return { transactionHash: "A".repeat(64), height: 1235, code };
      },
      disconnect: () => {},
    } as unknown as TxClient;
  };
  return { connection, factory, counts: () => ({ signatures, broadcasts }) };
}

test("direct signer simulates first, uses explicit fee, rejects wallet document changes and reports failed inclusion", async () => {
  const c = chainConfig(chain),
    intent = makeIntent(c, walletRead(), owner, "cancel_wallet_change");
  const h = transactionDouble();
  const prepared = await prepareTransaction(intent, h.connection, h.factory);
  expect(h.counts()).toEqual({ signatures: 0, broadcasts: 0 });
  expect(prepared.fee).toEqual({
    amount: [{ amount: "14000", denom: "utest" }],
    gas: "140000",
  });
  const result = await prepared.submit(async () => {});
  expect(result).toEqual({ hash: "A".repeat(64), height: 1235, code: 0 });
  expect(h.counts()).toEqual({ signatures: 1, broadcasts: 1 });
  await expect(prepared.submit(async () => {})).rejects.toThrow(
    "no longer valid",
  );
  const changed = transactionDouble(true);
  const p2 = await prepareTransaction(
    intent,
    changed.connection,
    changed.factory,
  );
  await expect(p2.submit(async () => {})).rejects.toThrow(
    "No broadcast was requested",
  );
  expect(changed.counts()).toEqual({ signatures: 1, broadcasts: 0 });
  const rejected = transactionDouble(false, 12);
  const p3 = await prepareTransaction(
    intent,
    rejected.connection,
    rejected.factory,
  );
  expect((await p3.submit(async () => {})).code).toBe(12);
  const stale = transactionDouble();
  const p4 = await prepareTransaction(intent, stale.connection, stale.factory);
  let freshnessChecks = 0;
  await expect(
    p4.submit(async () => {
      if (++freshnessChecks === 3)
        throw new Error("state changed during signing");
    }),
  ).rejects.toThrow("No broadcast was requested");
  expect(stale.counts()).toEqual({ signatures: 1, broadcasts: 0 });
  const unavailable = transactionDouble(false, 0, true);
  await expect(
    prepareTransaction(intent, unavailable.connection, unavailable.factory),
  ).rejects.toThrow("No signature or broadcast");
  expect(unavailable.counts()).toEqual({ signatures: 0, broadcasts: 0 });
});
