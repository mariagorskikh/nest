import { neon } from "@neondatabase/serverless";

/**
 * Nanda Town's Postgres connection (Neon).
 *
 * We create the client lazily and read DATABASE_URL at call time so that
 * importing this module never throws during the build step. In dev the URL
 * comes from .env.local; in production set it in your host's env vars.
 */
let client: ReturnType<typeof neon> | null = null;

export function sql() {
  if (!client) {
    const url = process.env.DATABASE_URL;
    if (!url) {
      throw new Error("DATABASE_URL is not set. Add it to .env.local.");
    }
    client = neon(url);
  }
  return client;
}

/**
 * Bring the schema up to date once per server process. Every statement is
 * idempotent (`if not exists`), so this is safe to call on every request.
 */
let schemaReady: Promise<void> | null = null;

export function ensureSchema(): Promise<void> {
  if (!schemaReady) {
    schemaReady = migrate();
  }
  return schemaReady;
}

async function migrate(): Promise<void> {
  const db = sql();

  // Base table. Fresh databases get every column up front.
  await db`
    create table if not exists skills (
      id           uuid primary key default gen_random_uuid(),
      name         text not null,
      author       text,
      description  text,
      source_type  text not null check (source_type in ('url', 'github', 'content')),
      source_url   text,
      content      text,
      endpoints    text,
      tags         text,
      reachable    boolean,
      email        text,
      github_username text,
      submitter_ip text,
      created_at   timestamptz not null default now(),
      updated_at   timestamptz not null default now()
    )
  `;

  // Existing (production) databases predate the columns above. `create table
  // if not exists` never alters an existing table, so these ALTERs are what
  // actually backfill the live registry. Each is idempotent.
  await db`alter table skills add column if not exists email text`;
  await db`alter table skills add column if not exists github_username text`;
  await db`alter table skills add column if not exists submitter_ip text`;
  await db`alter table skills add column if not exists updated_at timestamptz not null default now()`;

  // Append-only audit log: one row per create/edit with a full snapshot.
  // This is the "edit history" — never served through the public API, so it
  // may hold the private columns (email, ip).
  await db`
    create table if not exists skill_history (
      id         uuid primary key default gen_random_uuid(),
      skill_id   uuid not null references skills(id) on delete cascade,
      action     text not null check (action in ('created', 'updated')),
      snapshot   jsonb not null,
      created_at timestamptz not null default now()
    )
  `;
}
