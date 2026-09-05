"use server";

import { revalidatePath, revalidateTag } from "next/cache";
import { headers } from "next/headers";
import { createSkill, SKILLS_CACHE_TAG } from "@/lib/skills";
import { initialSubmitState, type SubmitState } from "./form-state";
import { validateSkillSubmission } from "@/lib/skill-submission";

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

export async function submitSkill(
  _prev: SubmitState,
  formData: FormData,
): Promise<SubmitState> {
  const fields = Object.fromEntries(formData.entries());
  const validated = validateSkillSubmission(fields);
  if (!validated.ok) {
    return { ...initialSubmitState, error: validated.error };
  }

  // --- Save ---------------------------------------------------------------
  try {
    const submitterIp = await clientIp();
    const skill = await createSkill({
      ...validated.value,
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
