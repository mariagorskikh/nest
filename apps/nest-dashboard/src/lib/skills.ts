import { unstable_cache } from "next/cache";
import { ensureSchema, sql } from "./db";

/** Bust with revalidateTag(SKILLS_CACHE_TAG) after any skill write. */
export const SKILLS_CACHE_TAG = "skills-list";

export type SkillSourceType = "url" | "github" | "content";

/** A SkillMD submission as stored in the database. */
export interface Skill {
  id: string;
  name: string;
  author: string | null;
  description: string | null;
  source_type: SkillSourceType;
  source_url: string | null;
  content: string | null;
  endpoints: string | null;
  tags: string | null;
  reachable: boolean | null;
  created_at: string;
}

/** Fields accepted when creating a new SkillMD submission. */
export interface NewSkill {
  name: string;
  author?: string | null;
  description?: string | null;
  source_type: SkillSourceType;
  source_url?: string | null;
  content?: string | null;
  endpoints?: string | null;
  tags?: string | null;
  reachable?: boolean | null;
  /** Private — for follow-up. Stored, but never returned by the public API. */
  email?: string | null;
  /** Private — GitHub handle, so we can find the submitter's hackathon PR. */
  github_username?: string | null;
  /** Private — submitter IP, captured server-side. Never returned publicly. */
  submitter_ip?: string | null;
}

/** One entry in a skill's append-only audit log. */
export interface SkillHistoryEntry {
  id: string;
  skill_id: string;
  action: "created" | "updated";
  snapshot: Record<string, unknown>;
  created_at: string;
}

export async function listSkills(): Promise<Skill[]> {
  await ensureSchema();
  const db = sql();
  const rows = await db`
    select id, name, author, description, source_type, source_url,
           content, endpoints, tags, reachable, created_at
    from skills
    order by created_at desc
  `;
  return rows as unknown as Skill[];
}

/**
 * Cached read for the hot paths (/skills page, GET /api/skills). The full
 * list carries every SkillMD's content, so serving it straight from Neon on
 * each request burns the data-transfer quota — this took the site down
 * during the submission rush. One Neon fetch per 30s worst case; skill
 * writes bust the tag immediately.
 */
export const listSkillsCached = unstable_cache(listSkills, [SKILLS_CACHE_TAG], {
  revalidate: 30,
  tags: [SKILLS_CACHE_TAG],
});

export async function getSkill(id: string): Promise<Skill | null> {
  await ensureSchema();
  const db = sql();
  const rows = await db`
    select id, name, author, description, source_type, source_url,
           content, endpoints, tags, reachable, created_at
    from skills
    where id = ${id}
  `;
  return (rows as unknown as Skill[])[0] ?? null;
}

export async function createSkill(input: NewSkill): Promise<Skill> {
  await ensureSchema();
  const db = sql();
  const id = crypto.randomUUID();
  const [rows] = await db.transaction((tx) => [
    tx`
      insert into skills
        (id, name, author, description, source_type, source_url, content,
         endpoints, tags, reachable, email, github_username, submitter_ip)
      values
        (${id}, ${input.name}, ${input.author ?? null}, ${input.description ?? null},
         ${input.source_type}, ${input.source_url ?? null}, ${input.content ?? null},
         ${input.endpoints ?? null}, ${input.tags ?? null}, ${input.reachable ?? null},
         ${input.email ?? null}, ${input.github_username ?? null}, ${input.submitter_ip ?? null})
      returning id, name, author, description, source_type, source_url,
                content, endpoints, tags, reachable, created_at
    `,
    // The transaction keeps the public row and its private audit snapshot
    // all-or-nothing. Build the snapshot from the inserted row so its database
    // timestamp and normalized columns are the committed values.
    tx`
      insert into skill_history (skill_id, action, snapshot)
      select id, 'created', jsonb_build_object(
        'id', id,
        'name', name,
        'author', author,
        'description', description,
        'source_type', source_type,
        'source_url', source_url,
        'content', content,
        'endpoints', endpoints,
        'tags', tags,
        'reachable', reachable,
        'created_at', created_at,
        'email', email,
        'github_username', github_username,
        'submitter_ip', submitter_ip
      )
      from skills
      where id = ${id}
    `,
  ]);

  const skill = (rows as unknown as Skill[])[0];
  if (!skill) throw new Error("Catalog transaction returned no skill row.");
  return skill;
}

/**
 * The full audit trail for one skill, newest first. Admin-only — the snapshots
 * contain private fields (email, ip), so never return this from a public route.
 */
export async function getSkillHistory(
  skillId: string,
): Promise<SkillHistoryEntry[]> {
  await ensureSchema();
  const db = sql();
  const rows = await db`
    select id, skill_id, action, snapshot, created_at
    from skill_history
    where skill_id = ${skillId}
    order by created_at desc
  `;
  return rows as unknown as SkillHistoryEntry[];
}
