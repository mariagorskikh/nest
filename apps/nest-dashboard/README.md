# Nanda Town dashboard

This Next.js application is the public Nanda Town manual, historical gallery,
SkillMD discovery catalog, and evidence visualizer. It does not run Town agents;
the Python `nandatown` CLI in the repository root performs Lab, Track, and Path
runs and writes evidence bundles.

## Local development

Use Node.js 22.12 or newer. From `apps/nest-dashboard`:

```bash
npm ci --ignore-scripts --no-audit --no-fund
cp .env.example .env.local
npm run dev
```

Open <http://localhost:3000>. Pages that read the SkillMD catalog require a
Postgres connection in `DATABASE_URL`; static documentation and local tests do
not. The application creates or advances its catalog tables on first database
use, so the configured database role needs permission to run the idempotent
`CREATE TABLE` and `ALTER TABLE` statements in `src/lib/db.ts`.

## Environment

Copy `.env.example` to `.env.local` for development. Never commit a populated
environment file.

- `DATABASE_URL` is required for the SkillMD catalog and voting data.
- `AUTH_SECRET`, `APP_BASE_URL`, `GOOGLE_CLIENT_ID`, and
  `GOOGLE_CLIENT_SECRET` are required together to enable Google sign-in and
  authenticated catalog voting. `APP_BASE_URL` must be the exact public HTTPS
  origin registered with the OAuth provider.
- `GITHUB_TOKEN` is optional and raises the server-side GitHub API allowance for
  the historical PR gallery.
- `GITHUB_WEBHOOK_SECRET` is optional and authenticates cache-revalidation
  requests to `/api/github/webhook`.

No environment variable is intentionally exposed to client JavaScript.

## Catalog boundary

`POST /api/skills` accepts JSON up to 256 KiB and uses the same semantic and
field validation as the HTML form. Source URLs are validated as HTTP(S) syntax
only: submission does not fetch, install, host, authorize, endorse, or execute
the linked content. A catalog insert and its audit-history row commit in one
database transaction.

Maximum field lengths are 200 characters for `name` and `author`, 254 for
`email`, 39 for `github_username`, 2,000 for `description`, 2,048 for
`source_url`, 200,000 for inline `content`, 8,192 for `endpoints`, and 512 for
`tags`.

For compatibility, `GET /api/skills` still returns the complete public catalog
in `{ count, skills }` rather than silently paginating or truncating it. The
per-entry limits bound new records, not aggregate catalog growth. A production
deployment therefore still needs gateway-wide body/rate controls and database
resource monitoring. Changing the listing contract should be a separately
versioned API decision.

## Verification

Run the dashboard checks from this directory:

```bash
npm test
npm run typecheck
npm run lint
npm run build
```

The tests exercise the API handler, shared API/form validation, the React form
action lifecycle, the database transaction boundary, and current/legacy trace
adapters with network access blocked. The transaction test simulates the Neon
transaction interface; it is not a live database integration test. The suite
does not prove browser hydration, a deployed server, global abuse controls, or
external agent adoption.

## Deployment

The app is a runtime Next.js server, not a static export. A generic deployment
from this directory is:

```bash
npm ci --ignore-scripts --no-audit --no-fund
npm run build
npm run start
```

The dashboard uses local system font stacks so production builds do not depend
on downloading font assets.

For Railway, set the service root directory to `apps/nest-dashboard`. The
checked-in `nixpacks.toml` selects Node 22 and runs the same install/build/start
sequence; `railway.json` checks `/` for health. Configure the environment above
in the service rather than uploading `.env.local`.

The dashboard CI job in `.github/workflows/ci.yml` uses Node 22 and gates tests,
type checking, lint, and the production build.
