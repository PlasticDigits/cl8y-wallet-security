// Official APIs and verified support limits are recorded in frontend/README.md.
export type WalletKind = "keplr" | "station";
export type WalletKey = {
  bech32Address: string;
  algo: string;
  pubKey: Uint8Array;
};
export type ArbitrarySignature = {
  pub_key: { type: string; value: string };
  signature: string;
};
export type InjectedWallet = {
  enable(chainId: string): Promise<void>;
  getKey(chainId: string): Promise<WalletKey>;
  signArbitrary(
    chainId: string,
    signer: string,
    data: string,
  ): Promise<ArbitrarySignature>;
};
declare global {
  interface Window {
    keplr?: InjectedWallet;
    station?: { keplr?: InjectedWallet };
  }
}
export function provider(kind: WalletKind): InjectedWallet {
  const wallet = kind === "station" ? window.station?.keplr : window.keplr;
  if (
    !wallet ||
    typeof wallet.enable !== "function" ||
    typeof wallet.getKey !== "function" ||
    typeof wallet.signArbitrary !== "function"
  ) {
    throw new Error(
      `${kind === "station" ? "Station" : "Keplr-compatible"} ADR-036 provider is unavailable. Use a browser with an injected wallet supporting the configured Terra Classic chain.`,
    );
  }
  return wallet;
}
export async function connect(kind: WalletKind, chainId: string) {
  if (!chainId)
    throw new Error(
      "The service has not configured a chain. Wallet connection is unavailable.",
    );
  if (chainId !== "columbus-5")
    throw new Error(
      "This frontend supports Terra Classic columbus-5 only. The configured chain is unsupported.",
    );
  const wallet = provider(kind);
  try {
    await wallet.enable(chainId);
    const key = await wallet.getKey(chainId);
    if (
      key.algo !== "secp256k1" ||
      !key.bech32Address.startsWith("terra1") ||
      key.pubKey.length !== 33
    ) {
      throw new Error();
    }
    return { kind, chainId, address: key.bech32Address, wallet };
  } catch {
    throw new Error(
      "Wallet connection was not completed. Unlock the wallet, select Terra Classic, and check that the configured chain and secp256k1 account are supported.",
    );
  }
}
export type Connection = Awaited<ReturnType<typeof connect>>;
export async function checkAccount(connection: Connection, expected: string) {
  let key: WalletKey;
  try {
    key = await connection.wallet.getKey(connection.chainId);
  } catch {
    throw new Error(
      "Cannot read the wallet account. Reconnect and request a fresh challenge.",
    );
  }
  if (key.bech32Address !== expected)
    throw new Error(
      "The selected wallet account changed. Reconnect and request a fresh challenge.",
    );
}
export function validateSignature(result: ArbitrarySignature) {
  try {
    const key = atob(result.pub_key.value);
    const signature = atob(result.signature);
    if (
      result.pub_key.type !== "tendermint/PubKeySecp256k1" ||
      key.length !== 33 ||
      ![2, 3].includes(key.charCodeAt(0)) ||
      signature.length !== 64
    )
      throw new Error();
  } catch {
    throw new Error(
      "This wallet did not return the required compressed secp256k1 ADR-036 signature. Nothing was verified.",
    );
  }
}
