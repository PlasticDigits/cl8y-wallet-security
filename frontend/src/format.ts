export function escapeHtml(value: unknown): string {
  return String(value ?? "").replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ]!,
  );
}
export function date(value: string | null | undefined): string {
  if (!value) return "Unavailable";
  const time = new Date(value);
  return Number.isFinite(time.getTime())
    ? time.toISOString().replace("T", " ").replace(".000Z", " UTC")
    : "Unavailable";
}
export function remaining(deadline: string, now: number): string {
  const delta = Date.parse(deadline) - now;
  if (!Number.isFinite(delta)) return "Countdown unavailable";
  if (delta <= 0) return "Deadline reached — refresh to confirm server status";
  const seconds = Math.ceil(delta / 1000);
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  return `${days ? `${days}d ` : ""}${hours}h ${minutes}m ${seconds % 60}s remaining (estimate)`;
}
// No Number conversion for token quantities. Only use with authoritative token decimals.
export function formatUnits(amount: string, decimals: number): string {
  if (
    !/^\d+$/.test(amount) ||
    !Number.isInteger(decimals) ||
    decimals < 0 ||
    decimals > 255
  ) {
    throw new Error("Invalid base-unit amount or token decimals");
  }
  const digits = amount.replace(/^0+(?=\d)/, "").padStart(decimals + 1, "0");
  if (decimals === 0) return digits;
  const fraction = digits.slice(-decimals).replace(/0+$/, "");
  return digits.slice(0, -decimals) + (fraction ? "." + fraction : "");
}
