/**
 * Display helpers for the hackathon marketplace UI.
 *
 * Kept separate from generated `hackathon-types.ts` so the type generator
 * can overwrite interfaces without losing hand-written utilities.
 */

import type { Dataset, LayerKey, Submission } from "./hackathon-types";

export const EMPTY_STATS = {
  total_submissions: 0,
  unique_participants: 0,
  layers_covered: 0,
  layers_total: 12,
  total_lines_added: 0,
  total_files_changed: 0,
};

export const EMPTY_DATASET: Dataset = {
  generated_at: "",
  stats: EMPTY_STATS,
  layers: [],
  submissions: [],
};

export function findSubmissionById(
  dataset: Dataset,
  id: string,
): Submission | null {
  return dataset.submissions.find((s) => s.id === id) ?? null;
}

export function submissionsForLayer(
  dataset: Dataset,
  layer: LayerKey,
): Submission[] {
  return dataset.submissions.filter((s) => s.layer === layer);
}

export function formatScore(score: number | null | undefined): string {
  if (score === null || score === undefined) return "unscored";
  return score.toFixed(1);
}

export function formatLinesAdded(n: number | null | undefined): string {
  if (n === null || n === undefined) return "—";
  if (n >= 1000) return `${(n / 1000).toFixed(1)}k`;
  return String(n);
}

/** Rubric dimensions in display order (matches scripts/judge/rubric.md). */
export const SCORE_DIMENSIONS = [
  { key: "correctness", label: "Correctness" },
  { key: "test_rigor", label: "Test Rigor" },
  { key: "api_fit", label: "API Fit" },
  { key: "docs_quality", label: "Docs Quality" },
  { key: "novelty", label: "Novelty" },
  { key: "persona_fidelity", label: "Persona Fidelity" },
] as const;

export type ScoreDimension = (typeof SCORE_DIMENSIONS)[number]["key"];
