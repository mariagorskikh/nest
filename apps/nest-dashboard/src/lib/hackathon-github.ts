// Server-only module (uses Next's cache APIs): import from Server
// Components and route handlers, never from client components.
import { unstable_cache } from "next/cache";
import type {
  Dataset,
  LayerKey,
  LayerStats,
  Submission,
  SubmissionAuthor,
} from "./hackathon-types";

/**
 * Live GitHub adapter for the hackathon marketplace.
 *
 * Replaces the deploy-time `public/hackathon-data.json` snapshot with a
 * request-time fetch of projnanda/nandatown pull requests, so merged PRs
 * appear in their layer automatically. The classification rules are a
 * faithful port of `packages/nest-marketplace/nest_marketplace/adapter.py`
 * — keep the two in sync.
 *
 * Rate limits: anonymous GitHub REST allows 60 requests/hour/IP. The PR
 * list costs one request per 100 PRs (currently 2). The RAW responses are
 * ~2.7MB/page — over Next's 2MB per-entry fetch-cache limit — so we cache
 * the compact PROCESSED dataset via unstable_cache (PR bodies truncated)
 * for REVALIDATE_SECONDS, tagged `hackathon-prs` so the GitHub webhook
 * (src/app/api/github/webhook) can bust it the moment a PR merges. Set
 * GITHUB_TOKEN in the environment for 5000/hour headroom; everything
 * works without it.
 */

export const GITHUB_REPO = "projnanda/nandatown";
export const PR_CACHE_TAG = "hackathon-prs";
const REVALIDATE_SECONDS = 300;
// Page ceiling. The repo has ~110 PRs; 10 pages (1000 newest) leaves wide
// headroom so a modest junk-PR flood can't push real hackathon entries off
// the end before the deadline. Hackathon filtering happens after the fetch.
const MAX_PAGES = 10;
// Hard cap on each PR body kept in the cached dataset. Keeps the whole
// serialized dataset far below Next's 2MB per-cache-entry ceiling even in a
// flood; the detail page links to GitHub for the untruncated body.
const BODY_CAP = 4000;

const KNOWN_LAYERS = [
  "transport",
  "communication",
  "identity",
  "registry",
  "auth",
  "trust",
  "payments",
  "coordination",
  "negotiation",
  "memory",
  "privacy",
  "datafacts",
] as const;

type KnownLayer = (typeof KNOWN_LAYERS)[number];

const LAYER_LABELS: Record<KnownLayer | "other", string> = {
  transport: "Transport",
  communication: "Communication",
  identity: "Identity",
  registry: "Registry",
  auth: "Auth",
  trust: "Trust",
  payments: "Payments",
  coordination: "Coordination",
  negotiation: "Negotiation",
  memory: "Memory",
  privacy: "Privacy",
  datafacts: "Data Facts",
  other: "Other",
};

const LAYER_BLURBS: Record<KnownLayer | "other", string> = {
  transport: "How bytes move between agents.",
  communication: "Message framing and request/response semantics.",
  identity: "Sign and verify per-agent payloads.",
  registry: "Publish and discover agent cards.",
  auth: "Issue, verify, and revoke capability tokens.",
  trust: "Reputation scores, attestations, reports.",
  payments: "Quote, pay, verify, refund.",
  coordination: "Group decisions and task allocation.",
  negotiation: "Bilateral bargaining.",
  memory: "Shared key-value with subscribe and CAS.",
  privacy: "Encryption and zero-knowledge proofs.",
  datafacts: "Dataset publish, fetch, and ACL.",
  other: "Builds that reach beyond the twelve layers.",
};

/* Ported verbatim from adapter.py `_THEME_TO_LAYER`. Order matters. */
const THEME_TO_LAYER: [RegExp, KnownLayer][] = [
  [/\btransport\b/, "transport"],
  [/\b(?:netem|latency|tail-latency)\b/, "transport"],
  [/\bcomm(?:unication)?\b/, "communication"],
  [/\bidentity\b|\bdid[-_]?key\b|\bsigning\b/, "identity"],
  [/\bregistry\b/, "registry"],
  [/\bauth\b|\bdpop\b|\bjwt\b|\bcapability\b/, "auth"],
  [/\beigentrust\b|\breputation\b|\btrust\b|\bstaking\b/, "trust"],
  [/\bescrow\b|\bpayments?\b|\bhtlc\b|\bprepaid\b/, "payments"],
  [/\bsealed-bid\b|\bauction\b|\bcoordination\b|\bcontract-net\b|\bconsensus\b|\bbft\b|\bquorum\b/, "coordination"],
  [/\bnegotiat/, "negotiation"],
  [/\bmemory\b|\bsemantic\b|\bblackboard\b|\bcrdt\b/, "memory"],
  [/\bprivacy\b|\bzk\b|\bencrypt/, "privacy"],
  [/\bdatafact|\bdataset\b|\bprovenance\b/, "datafacts"],
];

/* The ten scripted personas from the warm-up round (adapter.py AGENT_HANDLES). */
const AGENT_HANDLES = [
  "mit-undergrad",
  "harvard-phd",
  "cybersec-blackhat",
  "google-staff",
  "stanford-ml-phd",
  "coinbase-crypto",
  "meta-backend",
  "openai-llm",
  "cmu-robotics",
  "linux-kernel",
];

export function extractHandleAndTheme(
  branch: string,
): { handle: string | null; theme: string | null } {
  if (!branch.startsWith("hackathon/")) return { handle: null, theme: null };
  const rest = branch.slice("hackathon/".length);
  if (!rest) return { handle: null, theme: null };
  for (const handle of AGENT_HANDLES) {
    if (rest.startsWith(`${handle}-`)) {
      return { handle, theme: rest.slice(handle.length + 1) };
    }
  }
  const dash = rest.indexOf("-");
  if (dash === -1) return { handle: rest, theme: null };
  return { handle: rest.slice(0, dash), theme: rest.slice(dash + 1) || null };
}

// The plural "comms" is matched only against the title/body, never the branch
// slug: a stale slug like "versioned-comms" on an auth PR (PR #104) would
// otherwise hijack the layer, while a real comms PR still surfaces via its
// title (PR #18, a merged "versioned comms layer").
const COMMS_PLURAL = /\bcomms\b/;

export function classifyLayer(
  theme: string | null,
  title = "",
  body = "",
): LayerKey {
  const sources: Array<{ text: string; commsPlural: boolean }> = [
    { text: theme ?? "", commsPlural: false },
    { text: title.toLowerCase(), commsPlural: true },
    { text: body.toLowerCase(), commsPlural: true },
  ];
  for (const { text, commsPlural } of sources) {
    if (!text) continue;
    if (commsPlural && COMMS_PLURAL.test(text)) return "communication";
    for (const [pattern, layer] of THEME_TO_LAYER) {
      if (pattern.test(text)) return layer;
    }
  }
  return "other";
}

/** Pull a short blurb out of a PR body (port of adapter.short_description). */
export function shortDescription(body: string, maxLen = 240): string {
  if (!body) return "";
  for (const rawLine of body.split("\n")) {
    const line = rawLine.trim();
    if (!line) continue;
    if (line.startsWith("#") || line.startsWith(">") || line.startsWith("```")) continue;
    const cleaned = line.replaceAll("**", "").replaceAll("`", "");
    if (cleaned.length <= maxLen) return cleaned;
    const cut = cleaned.slice(0, maxLen);
    for (const sep of [". ", "? ", "! "]) {
      const idx = cut.lastIndexOf(sep);
      if (idx >= maxLen / 2) return cut.slice(0, idx + 1).trim();
    }
    const space = cut.lastIndexOf(" ");
    if (space >= maxLen / 2) return cut.slice(0, space).trimEnd() + "…";
    return cut + "…";
  }
  return "";
}

/**
 * Strip private "claude.ai/code/session_…" attribution links — they 403
 * for everyone but the author and must never reach the public page.
 */
export function scrubSessionLinks(body: string): string {
  if (!body.includes("claude.ai/code/session")) return body;
  const kept = body
    .split("\n")
    .filter((line) => !line.includes("claude.ai/code/session"));
  return kept
    .join("\n")
    .replace(/(?:\n[ \t]*(?:-{3,}|\*{3,}|_{3,})[ \t]*)+\s*$/g, "")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

/**
 * Layer cards for a submission list. Exported so the EMPTY fallback can
 * keep the 13 layer pages alive (with zero counts) when GitHub is
 * unreachable, instead of 404ing them.
 */
export function layerStatsFor(submissions: Submission[]): LayerStats[] {
  return [...KNOWN_LAYERS, "other" as const].map((key) => {
    const bucket = submissions.filter((s) => s.layer === key);
    return {
      key,
      label: LAYER_LABELS[key],
      blurb: LAYER_BLURBS[key],
      submission_count: bucket.length,
      top_score: null,
      is_open: bucket.length === 0,
    };
  });
}

interface GitHubPR {
  number: number;
  state: "open" | "closed";
  title: string;
  body: string | null;
  html_url: string;
  diff_url: string;
  created_at: string;
  merged_at: string | null;
  head: { ref: string };
  user: { login: string; avatar_url: string; html_url: string } | null;
}

async function fetchAllPRs(): Promise<GitHubPR[]> {
  const out: GitHubPR[] = [];
  const headers: Record<string, string> = {
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "nandatown-dashboard",
  };
  if (process.env.GITHUB_TOKEN) {
    headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  }
  for (let page = 1; page <= MAX_PAGES; page++) {
    // no-store: the surrounding unstable_cache owns caching — these raw
    // pages are too large for the per-entry fetch cache anyway.
    const res = await fetch(
      `https://api.github.com/repos/${GITHUB_REPO}/pulls?state=all&per_page=100&sort=created&direction=desc&page=${page}`,
      { headers, cache: "no-store" },
    );
    if (!res.ok) {
      throw new Error(`GitHub PR list failed: ${res.status}`);
    }
    const batch = (await res.json()) as GitHubPR[];
    out.push(...batch);
    if (batch.length < 100) break;
  }
  // Deduplicate by PR number: because we page a live, mutating list sorted
  // by created_at, a PR opened mid-pagination shifts everything down and can
  // surface the same PR on two pages. Without this, duplicate ids double-count
  // stats and trip React's duplicate-key guard.
  const byNumber = new Map<number, GitHubPR>();
  for (const pr of out) {
    if (!byNumber.has(pr.number)) byNumber.set(pr.number, pr);
  }
  return [...byNumber.values()];
}

function toSubmission(pr: GitHubPR): Submission {
  const branch = pr.head.ref;
  const { handle, theme } = extractHandleAndTheme(branch);
  const login = pr.user?.login ?? null;
  const authorLogin = login || handle || "unknown";
  const isAgent = handle !== null && AGENT_HANDLES.includes(handle);
  const body = scrubSessionLinks(pr.body ?? "");

  const author: SubmissionAuthor = {
    handle: isAgent && handle ? handle : authorLogin,
    avatar_url: pr.user?.avatar_url || `https://github.com/${authorLogin}.png`,
    profile_url: pr.user?.html_url || `https://github.com/${authorLogin}`,
    kind: isAgent ? "agent" : "human",
  };

  return {
    id: String(pr.number),
    pr_number: pr.number,
    title: pr.title,
    short_description: shortDescription(body),
    // Capped so the whole cached dataset stays far below the cache entry
    // ceiling; the detail page links to GitHub for the untruncated body.
    body_markdown: body.length > BODY_CAP ? body.slice(0, BODY_CAP) + "\n\n…" : body,
    layer: classifyLayer(theme, pr.title, body),
    branch,
    author,
    pr_url: pr.html_url,
    diff_url: pr.diff_url || (pr.html_url ? `${pr.html_url}.diff` : ""),
    additions: null,
    deletions: null,
    changed_files: null,
    created_at: pr.created_at,
    merged_at: pr.merged_at,
    state: pr.merged_at ? "merged" : "open",
    score: null,
    tag: isAgent ? "agent-authored" : "human-authored",
  };
}

/**
 * Fetch and assemble the live dataset: every open or merged PR on the repo
 * (hackathon or not), classified into its layer (or "Other"), merged entries
 * flagged. Closed-but-unmerged PRs are dropped.
 */
async function buildLiveDataset(): Promise<Dataset> {
  const prs = await fetchAllPRs();
  const submissions = prs
    .filter((pr) => pr.state === "open" || pr.merged_at !== null)
    .map(toSubmission)
    .sort((a, b) =>
      a.created_at === b.created_at
        ? b.pr_number - a.pr_number
        : b.created_at.localeCompare(a.created_at),
    );

  const layers = layerStatsFor(submissions);

  const participants = new Set(submissions.map((s) => s.author.handle));
  const coveredOfTwelve = KNOWN_LAYERS.filter((key) =>
    submissions.some((s) => s.layer === key),
  ).length;

  return {
    generated_at: new Date().toISOString(),
    stats: {
      total_submissions: submissions.length,
      total_merged: submissions.filter((s) => s.state === "merged").length,
      unique_participants: participants.size,
      layers_covered: coveredOfTwelve,
      layers_total: KNOWN_LAYERS.length,
      total_lines_added: 0,
      total_files_changed: 0,
    },
    layers,
    submissions,
  };
}

/**
 * The cached entry point: one compact dataset per REVALIDATE_SECONDS
 * window (or until the webhook busts the `hackathon-prs` tag), shared by
 * every /hackathon page render.
 */
export const fetchLiveDataset = unstable_cache(
  buildLiveDataset,
  ["hackathon-live-dataset"],
  { revalidate: REVALIDATE_SECONDS, tags: [PR_CACHE_TAG] },
);
