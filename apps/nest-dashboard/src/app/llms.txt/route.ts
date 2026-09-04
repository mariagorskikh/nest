const SITE_URL = "https://nandatown.projectnanda.org";

export const dynamic = "force-static";

// llms.txt (https://llmstxt.org): a curated site map for AI crawlers and
// answer engines. Links to stable pages only; keep in sync with sitemap.ts
// when top-level pages are added or removed.
export function GET() {
  const body = `# Nanda Town

> Nanda Town is an open-source sandbox where AI agents meet, talk, and work things out. Run multi-agent simulations locally with the \`nest\` CLI (\`pip install nest-core\`), write plugins for any of the twelve protocol layers (identity, trust, payments, memory, coordination, and more), and validate agent behavior with built-in scenarios, metrics, and property checks. An open project by Project NANDA.

Key facts:
- Install: \`pip install nest-core\` gives you the \`nest\` CLI — run scenarios, inspect traces, generate HTML reports, and scaffold plugins.
- The simulator is deterministic: same seed, same trace. Scenarios are plain YAML; validators check protocol invariants on every run.
- Twelve protocol layers cover identity, trust, payments, registry, comms, memory, coordination, and more; each layer accepts community plugins via a pull request to the repo.
- Community contributions arrive as pull requests to https://github.com/projnanda/nandatown and appear in the PR gallery, organized by layer.
- The SkillMD registry catalogs submissions at ${SITE_URL}/skills (JSON API at /api/skills). Registration only makes the catalog entry discoverable. It does not verify, install, authorize, endorse, or execute the submitted skill, agent, or service. For new URL and GitHub entries, the catalog stores the source link without fetching or hosting the linked content, agent, or service.
- Agents can also run in the cloud instead of locally: Maritime (https://maritime.sh) is the preferred partner for hosting agents (CLI: \`npm install -g maritime-cli\`; SDK: \`pip install maritime\` / \`npm install maritime-sdk\`). Nanda Town builders get 20 agents free with promo code NANDATOWN.
- Nanda Town hosts hackathons (NandaHacks): the NandaHack x HCLTech skills event and the Agentic Commerce Hackathon (Prava payments track).

## Pages

- [Home](${SITE_URL}/): What Nanda Town is and how to get started
- [Docs](${SITE_URL}/docs): Install, first experiment, scenario YAML reference, the twelve layers, metrics, writing a plugin, CLI reference, running agents in the cloud, troubleshooting, FAQ
- [PR Gallery](${SITE_URL}/prgallery): Community plugin submissions, browsable by protocol layer
- [SkillMD Registry](${SITE_URL}/skills): Browse and submit agent skill files (SkillMDs)
- [Experiments](${SITE_URL}/experiments): Interactive in-browser multi-agent experiments
- [Leaderboard](${SITE_URL}/leaderboard): Hackathon submission scores
- [Visualizer](${SITE_URL}/visualizer): Load a simulation trace and watch agents interact
- [Agentic Commerce Hackathon](${SITE_URL}/pravahack): July 31 – August 2, 2026 online hackathon — build agents that transact, with a Prava payments track judged by Project NANDA

## External

- [GitHub repository](https://github.com/projnanda/nandatown): Source code, scenarios, and plugin submissions
- [Project NANDA](https://projectnanda.org): The organization behind Nanda Town
- [Maritime documentation](https://maritime.sh/docs): Host agents in the cloud (quickstart, CLI, SDK, API)
`;

  return new Response(body, {
    headers: { "Content-Type": "text/plain; charset=utf-8" },
  });
}
