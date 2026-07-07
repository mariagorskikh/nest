"use server";

import { lookup } from "node:dns/promises";
import { isIP } from "node:net";
import { revalidatePath } from "next/cache";
import { createSkill, type SkillSourceType } from "@/lib/skills";
import { initialSubmitState, type SubmitState } from "./form-state";

function str(value: FormDataEntryValue | null): string {
  return typeof value === "string" ? value.trim() : "";
}

function isValidHttpUrl(value: string): boolean {
  try {
    const u = new URL(value);
    return u.protocol === "http:" || u.protocol === "https:";
  } catch {
    return false;
  }
}

/** Parse a dotted-quad IPv4 string to a 32-bit unsigned int, or null if malformed. */
function ipv4ToInt(ip: string): number | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let n = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const value = Number(part);
    if (value > 255) return null;
    n = n * 256 + value;
  }
  return n >>> 0;
}

function ipv4InCidr(n: number, base: string, bits: number): boolean {
  const baseInt = ipv4ToInt(base);
  if (baseInt === null) return false;
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  return ((n & mask) >>> 0) === ((baseInt & mask) >>> 0);
}

function isBlockedIpv4(ip: string): boolean {
  const n = ipv4ToInt(ip);
  if (n === null) return true;
  return (
    ipv4InCidr(n, "0.0.0.0", 8) || // "this" network / unspecified
    ipv4InCidr(n, "10.0.0.0", 8) || // private
    ipv4InCidr(n, "100.64.0.0", 10) || // carrier-grade NAT
    ipv4InCidr(n, "127.0.0.0", 8) || // loopback
    ipv4InCidr(n, "169.254.0.0", 16) || // link-local (incl. cloud metadata)
    ipv4InCidr(n, "172.16.0.0", 12) || // private
    ipv4InCidr(n, "192.168.0.0", 16) || // private
    ipv4InCidr(n, "224.0.0.0", 4) || // multicast
    ipv4InCidr(n, "240.0.0.0", 4) // reserved / broadcast
  );
}

/**
 * True if an IP literal points at the local host or a private/internal
 * network. Keeps the reachability probe from being turned into an SSRF against
 * internal services or the cloud metadata endpoint (169.254.169.254).
 */
function isBlockedIp(ip: string): boolean {
  const family = isIP(ip);
  if (family === 4) return isBlockedIpv4(ip);
  if (family === 6) {
    const lower = ip.toLowerCase();
    const mapped = lower.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    if (mapped) return isBlockedIpv4(mapped[1]);
    if (lower === "::1" || lower === "::") return true; // loopback / unspecified
    if (/^fe[89ab]/.test(lower)) return true; // fe80::/10 link-local
    if (/^f[cd]/.test(lower)) return true; // fc00::/7 unique-local
    return false;
  }
  return true; // not a valid IP literal → refuse
}

/** Resolve a hostname and report whether any of its addresses are internal. */
async function hostResolvesToBlocked(hostname: string): Promise<boolean> {
  try {
    const addresses = await lookup(hostname, { all: true });
    return addresses.length === 0 || addresses.some((a) => isBlockedIp(a.address));
  } catch {
    // Unresolvable host — treat as unreachable (and unsafe to probe).
    return true;
  }
}

/**
 * Best-effort check that a submitted URL actually answers. Never throws — a
 * failed, slow, or unsafe request just records `false`; it never blocks the save.
 *
 * Redirects are followed manually so every hop's host can be re-validated. This
 * stops the probe from being used as an SSRF against localhost, private
 * networks, or the cloud metadata endpoint — including via a public URL that
 * redirects inward. (DNS rebinding between this lookup and the fetch is not
 * fully closed; that would need a pinned-IP dispatcher.)
 */
async function checkReachable(url: string): Promise<boolean> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 5000);
  try {
    let current = url;
    for (let hop = 0; hop < 5; hop++) {
      let parsed: URL;
      try {
        parsed = new URL(current);
      } catch {
        return false;
      }
      if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return false;
      if (await hostResolvesToBlocked(parsed.hostname)) return false;

      const res = await fetch(current, {
        signal: controller.signal,
        redirect: "manual",
        headers: { "user-agent": "NandaTown-SkillMD-Checker" },
      });
      if (res.status >= 300 && res.status < 400) {
        const location = res.headers.get("location");
        if (!location) return false;
        current = new URL(location, current).toString();
        continue;
      }
      return res.ok;
    }
    return false; // too many redirects
  } catch {
    return false;
  } finally {
    clearTimeout(timer);
  }
}

export async function submitSkill(
  _prev: SubmitState,
  formData: FormData,
): Promise<SubmitState> {
  const name = str(formData.get("name"));
  const author = str(formData.get("author"));
  const description = str(formData.get("description"));
  const endpoints = str(formData.get("endpoints"));
  const tags = str(formData.get("tags"));
  const sourceType = str(formData.get("source_type")) as SkillSourceType;
  const sourceUrl = str(formData.get("source_url"));
  const content = str(formData.get("content"));

  // --- Validation ---------------------------------------------------------
  if (!name) {
    return { ...initialSubmitState, error: "Give your SkillMD a name." };
  }
  if (!["url", "github", "content"].includes(sourceType)) {
    return { ...initialSubmitState, error: "Pick how you want to submit it." };
  }
  if ((sourceType === "url" || sourceType === "github") && !sourceUrl) {
    return { ...initialSubmitState, error: "Add the link to your SkillMD." };
  }
  if ((sourceType === "url" || sourceType === "github") && !isValidHttpUrl(sourceUrl)) {
    return { ...initialSubmitState, error: "That link doesn't look like a real URL." };
  }
  if (sourceType === "content" && content.length < 20) {
    return {
      ...initialSubmitState,
      error: "Paste the full SkillMD text — that looks too short.",
    };
  }

  // --- Best-effort reachability check for hosted links --------------------
  let reachable: boolean | null = null;
  if (sourceType === "url" || sourceType === "github") {
    reachable = await checkReachable(sourceUrl);
  }

  // --- Save ---------------------------------------------------------------
  try {
    const skill = await createSkill({
      name,
      author: author || null,
      description: description || null,
      source_type: sourceType,
      source_url: sourceType === "content" ? null : sourceUrl,
      content: sourceType === "content" ? content : null,
      endpoints: endpoints || null,
      tags: tags || null,
      reachable,
    });
    revalidatePath("/skills");
    return { ok: true, error: null, createdId: skill.id, createdName: skill.name };
  } catch (err) {
    console.error("submitSkill failed:", err);
    return {
      ...initialSubmitState,
      error: "Something went wrong saving it. Please try again.",
    };
  }
}
