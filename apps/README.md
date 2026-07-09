# Apps

Nanda Town ships two front-end surfaces:

## `apps/dashboard/` — static trace viewer

- **Entry:** `nest dashboard [trace.jsonl]`
- **Use when:** you want a quick offline trace viewer with zero Node/npm setup
- **Tech:** single HTML file + vendored `d3.min.js` (no CDN)
- **Note:** marked deprecated in favor of the Next.js app for new features

## `apps/nest-dashboard/` — full Next.js site

- **Entry:** `cd apps/nest-dashboard && npm run dev`
- **Use when:** hackathon marketplace, layer pages, visualizer, skills UI
- **Data:** reads `public/hackathon-data.json` (generated from fixtures — see below)
- **Skills registry:** requires Neon `DATABASE_URL`; `POST /api/skills` requires `NEST_SKILLS_API_KEY` in production (see [nest-dashboard/README.md](nest-dashboard/README.md))
- **CI:** `npm run ci` (typecheck, eslint, build)

### Regenerating hackathon data

```bash
uv run python -m nest_marketplace.build_data \
  --prs-fixture fixtures/hackathon_prs.json \
  --scores docs/hackathon/scores.json \
  --out apps/nest-dashboard/public/hackathon-data.json
```

CI verifies this file matches the fixture via `scripts/check_hackathon_data.py`.

### Regenerating TypeScript types

```bash
uv run python scripts/generate_hackathon_types.py
```

Display helpers live in `src/lib/hackathon-display.ts` (not overwritten).
