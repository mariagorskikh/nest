/** Block SSRF targets for server-side reachability probes. */
const BLOCKED_HOSTNAMES = new Set([
  "localhost",
  "metadata.google.internal",
]);
function isPrivateIpv4(host: string): boolean {
  const parts = host.split(".").map((p) => Number.parseInt(p, 10));
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n))) {
    return false;
  }
  const [a, b] = parts;
  if (a === 10) return true;
  if (a === 127) return true;
  if (a === 0) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  return false;
}
function isBlockedIpv6(host: string): boolean {
  if (host === "::" || host === "::1") return true;
  if (host.startsWith("fe80:")) return true;
  const firstHextet = host.split(":")[0] ?? "";
  if (firstHextet.startsWith("fc") || firstHextet.startsWith("fd")) return true;
  if (host.startsWith("::ffff:")) {
    return isPrivateIpv4(host.slice("::ffff:".length));
  }
  return false;
}
export function isSafeExternalUrl(raw: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    return false;
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return false;
  }
  const host = parsed.hostname.toLowerCase().replace(/\.$/, "");
  }
  if (isBlockedIpv6(host)) {
    return false;
  }
  if (isPrivateIpv4(host)) {
    return false;
  }
  return true;
}
export function sanitizeHttpHref(raw: string | null | undefined): string | null {
  if (!raw) return null;
  return isSafeExternalUrl(raw) ? raw : null;
}
