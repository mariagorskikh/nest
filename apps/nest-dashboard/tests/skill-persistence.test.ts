import { beforeEach, expect, test, vi } from "vitest";
import type { Skill } from "@/lib/skills";

type Query = { text: string; values: unknown[] };
type State = { skills: Skill[]; history: Record<string, unknown>[] };

const database = vi.hoisted(() => ({
  ensureSchema: vi.fn(async () => undefined),
  sql: vi.fn(),
}));

vi.mock("@/lib/db", () => database);

import { createSkill } from "@/lib/skills";

let state: State;
let failHistory: boolean;

function normalizedSql(strings: TemplateStringsArray): string {
  return strings.join(" ? ").replace(/\s+/g, " ").trim().toLowerCase();
}

function execute(query: Query, target: State): unknown[] {
  if (query.text.startsWith("insert into skills")) {
    const explicitId = query.text.includes("(id, name");
    const values = explicitId ? query.values : ["database-generated-id", ...query.values];
    const [id, name, author, description, sourceType, sourceUrl, content, endpoints, tags, reachable] = values;
    const row: Skill = {
      id: String(id),
      name: String(name),
      author: author as string | null,
      description: description as string | null,
      source_type: sourceType as Skill["source_type"],
      source_url: sourceUrl as string | null,
      content: content as string | null,
      endpoints: endpoints as string | null,
      tags: tags as string | null,
      reachable: reachable as boolean | null,
      created_at: "2026-09-04T12:00:00.000Z",
    };
    target.skills.push(row);
    return [row];
  }

  if (query.text.startsWith("insert into skill_history")) {
    if (failHistory) throw new Error("history unavailable");
    target.history.push({ skill_id: query.values.at(-1) });
    return [];
  }

  throw new Error(`Unexpected query: ${query.text}`);
}

function fakeDatabase() {
  const direct = (strings: TemplateStringsArray, ...values: unknown[]) =>
    Promise.resolve(execute({ text: normalizedSql(strings), values }, state));

  direct.transaction = async (
    build: (tx: (strings: TemplateStringsArray, ...values: unknown[]) => Query) => Query[],
  ) => {
    const pending: State = {
      skills: [...state.skills],
      history: [...state.history],
    };
    const tx = (strings: TemplateStringsArray, ...values: unknown[]): Query => ({
      text: normalizedSql(strings),
      values,
    });
    const results = build(tx).map((query) => execute(query, pending));
    state = pending;
    return results;
  };

  return direct;
}

beforeEach(() => {
  state = { skills: [], history: [] };
  failHistory = false;
  database.sql.mockReturnValue(fakeDatabase());
});

const input = {
  name: "Atomic example",
  source_type: "content" as const,
  content: "# Atomic example\n\nA complete SkillMD document.",
};

test("catalog creation and its history record commit together", async () => {
  const created = await createSkill(input);

  expect(created.name).toBe(input.name);
  expect(state.skills).toHaveLength(1);
  expect(state.history).toHaveLength(1);
});

test("a history failure leaves no catalog row behind", async () => {
  failHistory = true;

  await expect(createSkill(input)).rejects.toThrow("history unavailable");
  expect(state.skills).toEqual([]);
  expect(state.history).toEqual([]);
});
