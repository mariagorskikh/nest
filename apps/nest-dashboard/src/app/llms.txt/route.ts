const SITE_URL = "https://nandatown.projectnanda.org";
const REPO_URL = "https://github.com/projnanda/nandatown";

export const dynamic = "force-static";

// Curated machine-readable summary. Keep claims narrower than the canonical
// repository docs; this site documents and displays Town, while the CLI runs it.
export function GET() {
  const body = `# Nanda Town

> Nanda Town is an open-source, local-first integration lab for exact agent, service, and protocol paths. Its Python CLI runs Lab, Track, and Path workflows and writes stage-separated evidence that another operator can verify, inspect, and rerun. The website is a manual, catalog, and evidence viewer; it does not run agents.

Current facts:
- Install from the checked-out repository with Python 3.11 or newer: create a virtual environment, then run \`python -m pip install -e .\`. The executable is \`nandatown\`, not the legacy \`nest\` command.
- Lab runs deterministic scripted scenarios. Track coordinates subprocess or external participants over local HTTP. \`nandatown test-agent --url URL\` exercises an already-running A2A agent on an exact Path.
- A bundle's canonical records are \`profile.json\`, \`run.json\`, \`intents.jsonl\`, \`events.jsonl\`, and \`result.json\`; \`manifest.json\` commits to them. Stage states are passed, failed, not_enough_evidence, not_tested, and error.
- \`nandatown verify\` checks bundle integrity and reproduces the recorded evaluation. \`report\` and \`replay\` are read-only views; \`visualize\` writes an HTML view. Running the target again creates a new bundle instead of rewriting the original evidence.
- Partial coverage may produce a valid signed receipt. Town Proof requires a verified, fresh, passed result with every recorded stage covered. A signature is a key commitment, not proof of independent observation, safety, authorization, adoption, or endorsement.
- HTTP is the canonical participant boundary. MCP and A2A support are thin adapters to that boundary.
- Town-authored fixtures, reference agents, local end-to-end runs, and CI are not evidence of external adoption. External acceptance still requires an independently developed agent and another human/operator reproducing a useful result.
- The SkillMD registry only makes the catalog entry discoverable. It does not verify, install, authorize, endorse, or execute the submitted skill, agent, or service. For new URL and GitHub entries, the catalog stores the source link without fetching or hosting the linked content, agent, or service.

## Current pages

- [Home](${SITE_URL}/): Current purpose and the route to historical material
- [Manual](${SITE_URL}/docs): Install, Lab/Track/Path, evidence, receipts, Proof, adapters, and catalog boundaries
- [SkillMD catalog](${SITE_URL}/skills): Discover and submit catalog entries; JSON API at ${SITE_URL}/api/skills
- [Visualizer](${SITE_URL}/visualizer): Load current \`events.jsonl\` evidence or labeled legacy showcase traces
- [Agents demo](${SITE_URL}/agents): Synthetic illustrative map, not a live registry or traffic feed

## Historical and showcase pages

- [PR history](${SITE_URL}/prgallery): Repository PRs organized by the earlier Town's twelve-layer taxonomy; not a current plugin-adoption claim
- [Experiments](${SITE_URL}/experiments): Frozen legacy Tier 1 showcase fixtures, not current Town evidence
- [Leaderboard](${SITE_URL}/leaderboard): Frozen legacy sample metrics, not current benchmark evidence or hackathon scores
- [Legacy branch](${REPO_URL}/tree/archive/legacy): Preserved previous implementation
- [v1-final tag](${REPO_URL}/tree/v1-final): Frozen previous release

## Canonical repository references

- [README](${REPO_URL}/blob/main/README.md): Current command and evidence guide
- [Architecture](${REPO_URL}/blob/main/docs/architecture.md): Execution and trust boundaries
- [Operators](${REPO_URL}/blob/main/docs/operators.md): Reproducible run procedure
- [Test an existing agent](${REPO_URL}/blob/main/docs/testing-an-existing-agent.md): Current Path profile defaults and external acceptance procedure
- [Convergence](${REPO_URL}/blob/main/docs/convergence.md): Current versus proposed scope
`;

  return new Response(body, {
    headers: { "Content-Type": "text/plain; charset=utf-8" },
  });
}
