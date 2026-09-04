import { renderToStaticMarkup } from "react-dom/server";
import { NextRequest } from "next/server";
import { beforeEach, expect, test, vi } from "vitest";
import type { NewSkill, Skill } from "../src/lib/skills";
import { POST } from "../src/app/api/skills/route";
import { submitSkill } from "../src/app/skills/actions";
import { initialSubmitState } from "../src/app/skills/form-state";
import SkillsPage from "../src/app/skills/page";

// Replace external persistence and Next request/cache context, not the route,
// action, page, URL parser, form components, or React renderer. These are
// boundary tests, not a database transaction or Next server E2E test.
const external = vi.hoisted(() => ({
  createSkill: vi.fn(),
  listSkillsCached: vi.fn(),
}));
vi.mock("@/lib/skills", () => ({
  ...external,
  SKILLS_CACHE_TAG: "skills-list",
}));
vi.mock("@/lib/auth", () => ({ getSessionUser: async () => null }));
vi.mock("@/lib/likes", () => ({ listAllLikesCached: async () => ({}) }));
vi.mock("next/cache", () => ({
  revalidatePath: vi.fn(),
  revalidateTag: vi.fn(),
}));
vi.mock("next/headers", () => ({ headers: async () => new Headers() }));

const skill: Skill = {
  id: "4e39fd2b-b61d-467b-a788-882f1fc3ace3",
  name: "Example skill",
  author: null,
  description: null,
  source_type: "url",
  source_url: "https://example.test/skill.md",
  content: null,
  endpoints: null,
  tags: null,
  reachable: null,
  created_at: "2026-09-01T12:00:00Z",
};

beforeEach(() => {
  external.createSkill.mockImplementation(async (input: NewSkill) => ({
    ...skill,
    ...input,
  }));
  external.listSkillsCached.mockResolvedValue([skill]);
  // Any unexpected probe fails the test without making a network request.
  vi.stubGlobal("fetch", vi.fn(() => {
    throw new Error("Unexpected network request");
  }));
});

function request(body: unknown): NextRequest {
  return new NextRequest("http://localhost/api/skills", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
}

function form(fields: Record<string, string>): FormData {
  const data = new FormData();
  for (const [key, value] of Object.entries(fields)) data.set(key, value);
  return data;
}

for (const sourceType of ["url", "github"]) {
  for (const sourceUrl of ["", "not a URL", "/relative.md", "ftp://example.test/skill.md", "mailto:team@example.test"]) {
    test(`API rejects ${sourceType} source ${JSON.stringify(sourceUrl)} before saving`, async () => {
      const response = await POST(request({
        name: skill.name, source_type: sourceType, source_url: sourceUrl,
      }));
      expect(response.status).toBe(400);
      expect((await response.json()).error).toBeTypeOf("string");
      expect(external.createSkill).not.toHaveBeenCalled();
      expect(fetch).not.toHaveBeenCalled();
    });

    test(`form rejects ${sourceType} source ${JSON.stringify(sourceUrl)} before saving or probing`, async () => {
      const result = await submitSkill(initialSubmitState, form({
        name: skill.name, source_type: sourceType, source_url: sourceUrl,
      }));
      expect(result.ok).toBe(false);
      expect(result.error).toBeTypeOf("string");
      expect(external.createSkill).not.toHaveBeenCalled();
      expect(fetch).not.toHaveBeenCalled();
    });
  }

  for (const sourceUrl of ["http://example.test/skill.md", "https://example.test/skill.md"]) {
    test(`API saves ${sourceType} ${sourceUrl} without claiming a probe`, async () => {
      const response = await POST(request({
        name: skill.name, source_type: sourceType, source_url: `  ${sourceUrl}  `,
      }));
      expect(response.status).toBe(201);
      expect((await response.json()).skill).toMatchObject({
        source_type: sourceType, source_url: sourceUrl, reachable: null,
      });
      expect(external.createSkill).toHaveBeenCalledExactlyOnceWith(expect.objectContaining({
        source_type: sourceType, source_url: sourceUrl, reachable: null,
      }));
      expect(fetch).not.toHaveBeenCalled();
    });

    test(`form saves ${sourceType} ${sourceUrl} without claiming a probe`, async () => {
      const result = await submitSkill(initialSubmitState, form({
        name: skill.name, source_type: sourceType, source_url: `  ${sourceUrl}  `,
      }));
      expect(result.ok).toBe(true);
      expect(result.createdId).toBe(skill.id);
      expect(external.createSkill).toHaveBeenCalledExactlyOnceWith(expect.objectContaining({
        source_type: sourceType, source_url: sourceUrl, reachable: null,
      }));
      expect(fetch).not.toHaveBeenCalled();
    });
  }
}

test("pasted content needs no source URL or network check in either path", async () => {
  const fields = { name: skill.name, source_type: "content", content: "# Example\n\nA full skill description." };
  const response = await POST(request(fields));
  expect(response.status).toBe(201);
  expect((await response.json()).skill).toMatchObject({
    source_type: "content", source_url: null, content: fields.content, reachable: null,
  });
  const result = await submitSkill(initialSubmitState, form(fields));
  expect(result.ok).toBe(true);
  expect(external.createSkill).toHaveBeenLastCalledWith(expect.objectContaining({
    source_type: "content", source_url: null, content: fields.content, reachable: null,
  }));
  expect(fetch).not.toHaveBeenCalled();
});

for (const sourceType of ["url", "github"] as const) {
  for (const [reachable, expected, excluded] of [
    [null, "link not checked", ["link responded", "couldn’t reach link"]],
    [true, "link responded", ["link not checked", "couldn’t reach link"]],
    [false, "couldn’t reach link", ["link responded", "link not checked"]],
  ] as const) {
    test(`page distinguishes ${sourceType} reachability ${reachable}`, async () => {
      external.listSkillsCached.mockResolvedValue([{ ...skill, source_type: sourceType, reachable }]);
      // Resolve the page's data function, then render its real synchronous
      // element tree. This does not test the RSC wire protocol or hydration.
      const markup = renderToStaticMarkup(await SkillsPage({ searchParams: Promise.resolve({}) }));
      expect(markup).toContain(expected);
      for (const other of excluded) expect(markup).not.toContain(other);
      expect(markup).toContain("Open source");
      expect(fetch).not.toHaveBeenCalled();
    });
  }
}

test("page gives pasted content no link reachability badge", async () => {
  external.listSkillsCached.mockResolvedValue([{
    ...skill, source_type: "content", source_url: null, content: "# Example skill",
  }]);
  const markup = renderToStaticMarkup(await SkillsPage({ searchParams: Promise.resolve({}) }));
  expect(markup).not.toContain("link not checked");
  expect(markup).not.toContain("link responded");
  expect(markup).not.toContain("couldn’t reach link");
  expect(markup).not.toContain("Open source");
});
