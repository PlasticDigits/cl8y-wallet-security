import type {
  AminoSignResponse,
  OfflineAminoSigner,
  StdFee,
  StdSignDoc,
} from "@cosmjs/amino";
import type { SigningCosmWasmClient } from "@cosmjs/cosmwasm-stargate";
import type { Intent } from "./chain";
import { checkAccount } from "./wallet";
import type { Connection } from "./wallet";

export type TxClient = Pick<
  SigningCosmWasmClient,
  | "getChainId"
  | "getContract"
  | "queryContractSmart"
  | "simulate"
  | "signAndBroadcast"
  | "disconnect"
>;
export type ClientFactory = (
  url: string,
  signer: OfflineAminoSigner,
) => Promise<TxClient>;
export type Receipt = { hash: string; height: number; code: number };
export type Prepared = {
  intent: Intent;
  fee: StdFee;
  simulatedGas: number;
  submit: (guard: () => Promise<void>) => Promise<Receipt>;
  dispose: () => void;
};
export function canonical(value: unknown): string {
  if (Array.isArray(value)) return "[" + value.map(canonical).join(",") + "]";
  if (value && typeof value === "object")
    return (
      "{" +
      Object.entries(value)
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([key, item]) => JSON.stringify(key) + ":" + canonical(item))
        .join(",") +
      "}"
    );
  return JSON.stringify(value);
}
const defaultFactory: ClientFactory = async (url, signer) => {
  const [
    { SigningCosmWasmClient },
    { HttpClient, Tendermint37Client, Comet38Client, Comet1Client },
  ] = await Promise.all([
    import("@cosmjs/cosmwasm-stargate"),
    import("@cosmjs/tendermint-rpc"),
  ]);
  const transport = new HttpClient(url, 20_000);
  const probe = Tendermint37Client.create(transport);
  try {
    const version = (await probe.status()).nodeInfo.version;
    const comet = version.startsWith("0.38.")
      ? Comet38Client.create(transport)
      : version.startsWith("1.")
        ? Comet1Client.create(transport)
        : version.startsWith("0.37.")
          ? probe
          : undefined;
    if (!comet) throw new Error("Unsupported consensus RPC version");
    return await SigningCosmWasmClient.createWithSigner(comet, signer, {
      broadcastTimeoutMs: 60_000,
      broadcastPollIntervalMs: 3_000,
    });
  } catch (error) {
    probe.disconnect();
    throw error;
  }
};

export async function prepareTransaction(
  intent: Intent,
  connection: Connection,
  factory: ClientFactory = defaultFactory,
): Promise<Prepared> {
  if (!intent.config.gasPrice)
    throw new Error(
      "The operator has not configured a gas price. Transaction preparation is unavailable; no fee denomination or price was assumed.",
    );
  if (!connection.wallet.signAmino)
    throw new Error(
      "This injected wallet has no supported Amino transaction signer. ADR-036 login support alone is insufficient.",
    );
  await checkAccount(connection, intent.signer);
  const { GasPrice, calculateFee } = await import("@cosmjs/stargate");
  let gasPrice;
  try {
    gasPrice = GasPrice.fromString(intent.config.gasPrice);
  } catch {
    throw new Error(
      "The operator gas price cannot be parsed. Transaction preparation is unavailable.",
    );
  }
  if (connection.chainId !== intent.config.chainId)
    throw new Error("Wallet chain does not match the reviewed chain.");
  let fee: StdFee | undefined;
  let guard: (() => Promise<void>) | undefined;
  let active = true;
  let broadcastPossible = false;
  let consumed = false;
  const signer: OfflineAminoSigner = {
    getAccounts: async () => {
      await checkAccount(connection, intent.signer);
      const key = await connection.wallet.getKey(connection.chainId);
      return [
        {
          address: key.bech32Address,
          pubkey: key.pubKey,
          algo: "secp256k1" as const,
        },
      ];
    },
    signAmino: async (
      address: string,
      doc: StdSignDoc,
    ): Promise<AminoSignResponse> => {
      if (!active || !guard || !fee || address !== intent.signer)
        throw new Error("Review is no longer valid.");
      await guard();
      await checkAccount(connection, intent.signer);
      await verifyIdentities();
      const msg = doc.msgs[0];
      if (
        doc.chain_id !== intent.config.chainId ||
        doc.memo !== "" ||
        doc.msgs.length !== 1 ||
        msg?.type !== "wasm/MsgExecuteContract" ||
        msg.value.sender !== intent.signer ||
        msg.value.contract !== intent.token.address ||
        canonical(msg.value.msg) !== canonical(intent.msg) ||
        canonical(msg.value.funds) !== "[]" ||
        canonical(doc.fee) !== canonical(fee)
      )
        throw new Error(
          "The signing document differs from the reviewed transaction.",
        );
      const original = canonical(doc);
      const signed = await connection.wallet.signAmino!(
        connection.chainId,
        address,
        doc,
        { preferNoSetFee: true, preferNoSetMemo: true },
      );
      if (!active || canonical(signed.signed) !== original)
        throw new Error(
          "The wallet changed the reviewed document. No broadcast was requested.",
        );
      await checkAccount(connection, intent.signer);
      await guard();
      await verifyIdentities();
      broadcastPossible = true;
      return signed;
    },
  };
  let client: TxClient | undefined;
  const verifyIdentities = async () => {
    if (!client || (await client.getChainId()) !== intent.config.chainId)
      throw new Error("RPC chain mismatch");
    const info = await client.getContract(intent.token.address);
    if (String(info.codeId) !== intent.token.code_id)
      throw new Error("Contract code mismatch");
    const security = (await client.queryContractSmart(intent.token.address, {
      security_config: {},
    })) as { controller?: unknown };
    if (security.controller !== intent.config.controller)
      throw new Error("Controller mismatch");
  };
  try {
    client = await factory(intent.config.rpcUrl, signer);
    await verifyIdentities();
    const message = {
      typeUrl: "/cosmwasm.wasm.v1.MsgExecuteContract",
      value: {
        sender: intent.signer,
        contract: intent.token.address,
        msg: new TextEncoder().encode(JSON.stringify(intent.msg)),
        funds: [],
      },
    };
    const simulatedGas = await client.simulate(intent.signer, [message], "");
    const adjustedGas = Math.ceil(simulatedGas * intent.config.gasAdjustment);
    if (
      !Number.isSafeInteger(simulatedGas) ||
      simulatedGas <= 0 ||
      !Number.isSafeInteger(adjustedGas) ||
      adjustedGas <= 0
    )
      throw new Error("Unsupported gas estimate");
    fee = calculateFee(adjustedGas, gasPrice);
    if (!fee.amount.length || fee.amount.some((c) => BigInt(c.amount) <= 0n))
      throw new Error("No payable fee configured");
    const connectedClient = client;
    return {
      intent,
      fee,
      simulatedGas,
      dispose: () => {
        active = false;
        connectedClient.disconnect();
      },
      submit: async (check) => {
        if (!active || consumed)
          throw new Error(
            "This transaction review is no longer valid. Prepare a fresh review.",
          );
        consumed = true;
        guard = check;
        try {
          await check();
          await checkAccount(connection, intent.signer);
          const result = await connectedClient.signAndBroadcast(
            intent.signer,
            [message],
            fee!,
            "",
          );
          if (
            !/^[A-Fa-f0-9]{64}$/.test(result.transactionHash) ||
            !Number.isSafeInteger(result.height) ||
            !Number.isSafeInteger(result.code)
          )
            throw new Error("Unconfirmed transaction result");
          return {
            hash: result.transactionHash,
            height: result.height,
            code: result.code,
          };
        } catch {
          throw new Error(
            broadcastPossible
              ? "Transaction outcome is unconfirmed; it may have been broadcast. Fees may have been charged. Refresh chain state and check your wallet before preparing another transaction."
              : "Signing was declined, unsupported, or no longer matched the review. No broadcast was requested by this page. Refresh before retrying.",
          );
        } finally {
          active = false;
          connectedClient.disconnect();
        }
      },
    };
  } catch {
    client?.disconnect();
    throw new Error(
      "Simulation or RPC identity verification failed. No signature or broadcast was requested. Check chain/RPC availability, signer funds and contract conditions; no fallback gas or fee was used.",
    );
  }
}
