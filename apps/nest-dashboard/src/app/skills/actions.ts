"use server";

import { revalidatePath, revalidateTag } from "next/cache";
import { headers } from "next/headers";
import { createSkill, SKILLS_CACHE_TAG, type SkillSourceType } from "@/lib/skills";
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

function isValidEmail(value: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

/**
 * Reduce whatever the user typed to a bare GitHub handle: strip a leading "@",
 * a full "github.com/…" URL, and any trailing slash. Returns "" if nothing
 * usable is left.
 */
function normalizeGithubUsername(value: string): string {
  let v = value.trim().replace(/^@/, "");
  const urlMatch = v.match(/github\.com\/([^/\s?#]+)/i);
  if (urlMatch) v = urlMatch[1];
  return v.replace(/\/+$/, "").trim();
}

function isValidGithubUsername(value: string): boolean {
  // GitHub handles: 1–39 chars, alphanumeric or single hyphens, no leading/
  // trailing hyphen.
  return /^[a-zA-Z0-9](?:[a-zA-Z0-9]|-(?=[a-zA-Z0-9])){0,38}$/.test(value);
}

/**
 * Best-effort client IP from the proxy headers Railway sets. Falls back to
 * null when we can't tell (e.g. local dev without a proxy).
 */
async function clientIp(): Promise<string | null> {
  const h = await headers();
  const forwarded = h.get("x-forwarded-for");
  if (forwarded) return forwarded.split(",")[0].trim() || null;
  return h.get("x-real-ip");
}

/**
 * Best-effort check that a submitted URL actually answers. Never throws — a
 * failed or slow request just means we record `false`, we don't block the save.
 */
async function checkReachable(url: string): Promise<boolean> {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 5000);
    const res = await fetch(url, {
      signal: controller.signal,
      redirect: "follow",
      headers: { "user-agent": "NandaTown-SkillMD-Checker" },
    });
    clearTimeout(timer);
    return res.ok;
  } catch {
    return false;
  }
}

export async function submitSkill(
  _prev: SubmitState,
  formData: FormData,
): Promise<SubmitState> {
  const name = str(formData.get("name"));
  const author = str(formData.get("author"));
  const email = str(formData.get("email"));
  const githubUsername = normalizeGithubUsername(str(formData.get("github_username")));
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
  if (email && !isValidEmail(email)) {
    return { ...initialSubmitState, error: "That email doesn't look right." };
  }
  if (githubUsername && !isValidGithubUsername(githubUsername)) {
    return {
      ...initialSubmitState,
      error: "Enter just your GitHub username (e.g. octocat).",
    };
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
    const submitterIp = await clientIp();
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
      email: email || null,
      github_username: githubUsername || null,
      submitter_ip: submitterIp,
    });
    revalidateTag(SKILLS_CACHE_TAG, "max");
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
