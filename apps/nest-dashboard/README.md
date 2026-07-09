This is a [Next.js](https://nextjs.org) project for the Nanda Town hackathon marketplace, trace visualizer, and skills UI.

## Getting Started

```bash
npm ci
npm run dev
```

Open [http://localhost:3000](http://localhost:3000).

## Skills page (`/skills`) — Neon Postgres

The `/skills` route stores SkillMD submissions in Postgres via
[`@neondatabase/serverless`](https://neon.tech). Other pages work without a
database.

1. Create a free project at [neon.tech](https://neon.tech).
2. Copy the connection string from the Neon console.
3. Create `.env.local` from the template:

```bash
cp .env.local.example .env.local
# edit .env.local and set DATABASE_URL=postgresql://...
# optional in dev, required for POST in production:
# NEST_SKILLS_API_KEY=your-long-random-secret
```

4. Initialize the schema:

```bash
node scripts/db-init.mjs
```

Expected output: `CONNECTED: PostgreSQL ...` and `TABLE skills ready.`

From the repo root you can also use `.\scripts\deploy-local.ps1 -InitSkills
-DatabaseUrl "postgresql://..."`.

> **Note:** Local Docker Postgres does not work with
> `@neondatabase/serverless` (HTTP driver, not TCP). Use Neon.

## API security (`/api/skills`)

| Endpoint | Auth | Limits |
|----------|------|--------|
| `GET /api/skills` | Public read | — |
| `POST /api/skills` | `X-Skills-API-Key` header when `NEST_SKILLS_API_KEY` is set | 30 req/min/IP; 256 KB max body |

**Production (`NODE_ENV=production`):** `POST` returns **503** until
`NEST_SKILLS_API_KEY` is configured in `.env.local`.

**Development:** `POST` is allowed without the API key when
`NEST_SKILLS_API_KEY` is unset.

**SSRF protection:** Private and internal URLs (localhost, RFC1918,
link-local, metadata hosts) are blocked in the API route, server action
reachability probe, and rendered `source_url` links on `/skills`.

### Examples

Dev POST (no API key required when `NEST_SKILLS_API_KEY` is unset):

```bash
curl -X POST http://localhost:3000/api/skills \
  -H "Content-Type: application/json" \
  -d '{"name":"my-skill","source_type":"content","content":"# SkillMD\n\nFull skill text here..."}'
```

Production POST:

```bash
curl -X POST http://localhost:3000/api/skills \
  -H "Content-Type: application/json" \
  -H "X-Skills-API-Key: $NEST_SKILLS_API_KEY" \
  -d '{"name":"my-skill","source_type":"url","source_url":"https://example.com/skill.md"}'
```

SSRF attempt (rejected with 400):

```bash
curl -X POST http://localhost:3000/api/skills \
  -H "Content-Type: application/json" \
  -d '{"name":"bad","source_type":"url","source_url":"http://127.0.0.1/skill.md"}'
```

See [`docs/security-audit.md`](../../docs/security-audit.md) for the full
findings register.

## CI checks

```bash
npm run ci   # typecheck + eslint + next build
```

From the repo root: `make ci-dashboard`

## Regenerating data

Hackathon marketplace data is **not** fetched from GitHub in CI. Regenerate from the committed fixture:

```bash
uv run python -m nest_marketplace.build_data \
  --prs-fixture fixtures/hackathon_prs.json \
  --scores docs/hackathon/scores.json \
  --out apps/nest-dashboard/public/hackathon-data.json
```

Verify drift: `uv run python scripts/check_hackathon_data.py`

## Regenerating TypeScript types

```bash
uv run python scripts/generate_hackathon_types.py
```

Source of truth: `packages/nest-marketplace/nest_marketplace/adapter.py`. Display helpers live in `src/lib/hackathon-display.ts`.

See also [`apps/README.md`](../README.md).
