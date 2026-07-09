"use server";

import { revalidatePath } from "next/cache";
import { createSkill, type SkillSourceType } from "@/lib/skills";
import { isSafeExternalUrl } from "@/lib/url-safety";
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
  if ((sourceType === "url" || sourceType === "github") && !isSafeExternalUrl(sourceUrl)) {
    return {
      ...initialSubmitState,
      error: "That link isn't allowed — private or internal URLs are blocked for safety.",
    };
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
