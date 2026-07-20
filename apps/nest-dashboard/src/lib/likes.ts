import { unstable_cache } from "next/cache";
import { ensureSchema, sql } from "./db";
import type { SessionUser } from "./auth";

/** Bust with revalidateTag(LIKES_CACHE_TAG) after any like/unlike. */
export const LIKES_CACHE_TAG = "likes-all";

/** What the public sees about one liker. Subs stay server-side. */
export interface Liker {
  name: string;
  avatar: string | null;
}

export interface SkillLikeSummary {
  count: number;
  likers: Liker[];
  /** Provider subs of everyone who liked — used server-side only. */
  subs: string[];
}

/** All likes grouped by skill, oldest first within each skill. */
export async function listAllLikes(): Promise<Record<string, SkillLikeSummary>> {
  await ensureSchema();
  const db = sql();
  const rows = (await db`
    select skill_id, user_sub, user_name, user_avatar
    from skill_likes
    order by created_at asc
  `) as unknown as {
    skill_id: string;
    user_sub: string;
    user_name: string;
    user_avatar: string | null;
  }[];

  const map: Record<string, SkillLikeSummary> = {};
  for (const row of rows) {
    const entry = (map[row.skill_id] ??= { count: 0, likers: [], subs: [] });
    entry.count += 1;
    entry.likers.push({ name: row.user_name, avatar: row.user_avatar });
    entry.subs.push(row.user_sub);
  }
  return map;
}

/**
 * Cached read for the hot paths (/skills page, GET /api/likes) — one Neon
 * fetch per 30s worst case instead of the full likes table per visitor.
 * Like/unlike writes bust the tag, so voters still see counts move at once.
 */
export const listAllLikesCached = unstable_cache(listAllLikes, [LIKES_CACHE_TAG], {
  revalidate: 30,
  tags: [LIKES_CACHE_TAG],
});

/** Idempotent like. Returns false if the skill doesn't exist. */
export async function likeSkill(skillId: string, user: SessionUser): Promise<boolean> {
  await ensureSchema();
  const db = sql();
  try {
    await db`
      insert into skill_likes (skill_id, user_sub, user_name, user_avatar, provider)
      values (${skillId}, ${user.sub}, ${user.name}, ${user.avatar}, ${user.provider})
      on conflict (skill_id, user_sub) do nothing
    `;
    return true;
  } catch (err: unknown) {
    // 23503 foreign_key_violation → no such skill. 22P02 → not a uuid.
    const code = (err as { code?: string }).code;
    if (code === "23503" || code === "22P02") return false;
    throw err;
  }
}

export async function unlikeSkill(skillId: string, userSub: string): Promise<void> {
  await ensureSchema();
  const db = sql();
  await db`
    delete from skill_likes
    where skill_id = ${skillId} and user_sub = ${userSub}
  `;
}

/** Authoritative public view of one skill's likes, oldest first. */
export async function listLikers(skillId: string): Promise<Liker[]> {
  await ensureSchema();
  const db = sql();
  const rows = (await db`
    select user_name, user_avatar
    from skill_likes
    where skill_id = ${skillId}
    order by created_at asc
  `) as unknown as { user_name: string; user_avatar: string | null }[];
  return rows.map((row) => ({ name: row.user_name, avatar: row.user_avatar }));
}
