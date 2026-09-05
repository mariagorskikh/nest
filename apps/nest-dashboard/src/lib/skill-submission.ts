import { isValidHttpUrl } from "./skill-source";
import type { NewSkill, SkillSourceType } from "./skills";

export const MAX_SKILL_REQUEST_BYTES = 256 * 1024;

const FIELD_LIMITS = {
  name: 200,
  author: 200,
  email: 254,
  github_username: 39,
  description: 2_000,
  source_url: 2_048,
  content: 200_000,
  endpoints: 8_192,
  tags: 512,
} as const;

type FieldName = keyof typeof FIELD_LIMITS;

export type SkillSubmissionResult =
  | { ok: true; value: NewSkill }
  | { ok: false; error: string };

function stringValue(
  input: Record<string, unknown>,
  field: FieldName | "source_type",
  trim = true,
): string {
  const value = input[field];
  if (typeof value !== "string") return "";
  return trim ? value.trim() : value;
}

function normalizeGithubUsername(value: string): string {
  let normalized = value.trim().replace(/^@/, "");
  const urlMatch = normalized.match(/github\.com\/([^/\s?#]+)/i);
  if (urlMatch) normalized = urlMatch[1];
  return normalized.replace(/\/+$/, "").trim();
}

function isValidGithubUsername(value: string): boolean {
  return /^[a-zA-Z0-9](?:[a-zA-Z0-9]|-(?=[a-zA-Z0-9])){0,38}$/.test(value);
}

function isValidEmail(value: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

export function validateSkillSubmission(
  input: Record<string, unknown>,
): SkillSubmissionResult {
  const values = {
    name: stringValue(input, "name"),
    author: stringValue(input, "author"),
    email: stringValue(input, "email"),
    github_username: normalizeGithubUsername(stringValue(input, "github_username")),
    description: stringValue(input, "description"),
    source_url: stringValue(input, "source_url"),
    content: stringValue(input, "content", false),
    endpoints: stringValue(input, "endpoints"),
    tags: stringValue(input, "tags"),
  };

  for (const field of Object.keys(FIELD_LIMITS) as FieldName[]) {
    if (values[field].length > FIELD_LIMITS[field]) {
      return {
        ok: false,
        error: `${field} is too long (maximum ${FIELD_LIMITS[field]} characters).`,
      };
    }
  }

  const sourceType = stringValue(input, "source_type") as SkillSourceType;
  if (!values.name) return { ok: false, error: "name is required" };
  if (values.email && !isValidEmail(values.email)) {
    return { ok: false, error: "email must be a valid address" };
  }
  if (values.github_username && !isValidGithubUsername(values.github_username)) {
    return { ok: false, error: "github_username must be a valid GitHub username" };
  }
  if (!(["url", "github", "content"] as string[]).includes(sourceType)) {
    return {
      ok: false,
      error: "source_type must be one of: url, github, content",
    };
  }
  if ((sourceType === "url" || sourceType === "github") && !values.source_url) {
    return {
      ok: false,
      error: "source_url is required for url/github submissions",
    };
  }
  if (
    (sourceType === "url" || sourceType === "github") &&
    !isValidHttpUrl(values.source_url)
  ) {
    return { ok: false, error: "source_url must be a valid http(s) URL" };
  }
  if (sourceType === "content" && values.content.trim().length < 20) {
    return {
      ok: false,
      error: "content is required (and must be the full SkillMD)",
    };
  }

  return {
    ok: true,
    value: {
      name: values.name,
      author: values.author || null,
      description: values.description || null,
      source_type: sourceType,
      source_url: sourceType === "content" ? null : values.source_url,
      content: sourceType === "content" ? values.content : null,
      endpoints: values.endpoints || null,
      tags: values.tags || null,
      reachable: null,
      email: values.email || null,
      github_username: values.github_username || null,
    },
  };
}
