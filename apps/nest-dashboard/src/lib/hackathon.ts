/**
 * Server-only data loader for the /hackathon routes.
 *
 * Reads the static JSON written by `nest-marketplace-build` at the
 * repo root. The JSON shape is owned by `packages/nest-marketplace` —
 * keep `hackathon-types.ts` in sync with `nest_marketplace.adapter`.
 *
 * Why a static JSON instead of a request-time fetch?
 *
 * 1. Anonymous GitHub REST is rate-limited per-IP. A Railway deploy
 *    behind a shared egress will get 403'd within minutes if every
 *    page render touches `api.github.com`. Building once at deploy
 *    time keeps us well under the limit.
 * 2. The data is public and changes slowly (PRs land at human speed).
 *    Five-minute freshness is fine.
 * 3. Keeps secrets out: no token in the build, no token at runtime.
 *
 * This module imports `node:fs/promises` and is therefore not safe to
 * import from client components — the public surface is the types and
 * helpers in `./hackathon-types`.
 */
import fs from "node:fs/promises";
import path from "node:path";
import { EMPTY_DATASET } from "./hackathon-display";
import type { Dataset } from "./hackathon-types";
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}
function validateDataset(raw: unknown): Dataset | null {
  if (!isRecord(raw) || !Array.isArray(raw.submissions) || !isRecord(raw.stats)) {
    return null;
  }
  return raw as unknown as Dataset;
}
// Re-export generated types and display helpers from a single module.
export * from "./hackathon-types";
export * from "./hackathon-display";
/**
 * Read the static dataset JSON from `public/hackathon-data.json`.
 *
 * Never throws. If the file is missing or malformed (e.g. the build
 * step failed) we return an empty dataset and the UI shows its
 * graceful error state — same shape, zero rows.
 *
 * Cached for ~5 minutes per process (revalidate window) so a hot
 * production instance avoids hitting disk on every request.
 */
export async function loadDataset(): Promise<Dataset> {
  try {
    const filePath = path.join(
      process.cwd(),
      "public",
      "hackathon-data.json",
    );
    const raw = await fs.readFile(filePath, "utf8");
    const parsed = validateDataset(JSON.parse(raw));
    return parsed ?? EMPTY_DATASET;
  } catch {
    return EMPTY_DATASET;
  }
}
// Mark this module as revalidating at ~5 min intervals when used in a
// Server Component — keeps the build artifact warm without hitting
// disk on every request.
export const DATA_REVALIDATE_SECONDS = 300;
