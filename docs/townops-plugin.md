# Town Operations Triage Plugin

## Overview

The Town Operations (TownOps) plugin enables multi-agent coordination for triaging and resolving citizen-reported issues in a simulated town environment. It demonstrates how NANDA agents can collaborate on real-world service coordination tasks.

## Architecture

The system uses a pipeline of specialized agents:

```
Citizen Report → Triage Agent → Zone Dispatcher → Resolver Agent → Resident Agent → Citizen
                                      ↕
                              Coordinator Agent
```

### Agent Roles

| Agent | Count | Responsibility |
|-------|-------|----------------|
| **Triage Agent** | 1 | Classifies issues by type, severity, and zone |
| **Zone Dispatcher** | 2 | Routes issues to appropriate resolvers within zones |
| **Resolver Agent** | 1 | Executes the fix and reports completion |
| **Resident Agent** | 1 | Generates plain-language status updates for citizens |
| **Coordinator** | 1 | Manages SLA tracking and escalations |

### Issue Lifecycle

1. **Reported** → Citizen submits issue with description and location
2. **Classified** → Triage agent determines type, severity, and zone
3. **Dispatched** → Zone dispatcher assigns to appropriate resolver
4. **In Progress** → Resolver begins working on the issue
5. **Resolved** → Fix is confirmed and resident is notified
6. **Closed** → Citizen confirms resolution

### Severity Levels

| Level | SLA | Examples |
|-------|-----|----------|
| **Critical** | 2 hours | Fire, gas leak, downed power line |
| **High** | 12 hours | Road closure, water main break |
| **Medium** | 48 hours | Streetlight out, noise complaint |
| **Low** | 168 hours | Tree trimming, trash pickup |

## Usage

### Running the Scenario

```bash
# From the NANDA Town root
nest run scenarios/town_ops.yaml
```

### Custom Configuration

Edit `scenarios/town_ops.yaml` to adjust:
- Number of agents per role
- Zone definitions
- Issue types and SLA thresholds
- Failure injection rates

### Agent Templates

- `templates/agents/townops-triage-agent.yaml` — Triage agent configuration
- `templates/agents/townops-resident-agent.yaml` — Resident-facing agent configuration

## Integration with TownOps Skill

This scenario is designed to work with the [TownOps Skill](https://github.com/Rohan5commit/townops-skill), a deployed API that provides:

- 8 structured endpoints with Zod validation
- NVIDIA NIM AI integration for classification and summaries
- SQLite database with seeded demo issues
- Deterministic state machine with validated transitions
- Full Next.js 15 UI for human oversight

### API Endpoints (from TownOps Skill)

```
GET    /api/issues          — List and filter issues
POST   /api/issues          — Create new issue
GET    /api/issues/{id}     — Get issue detail with history
PATCH  /api/issues/{id}/status — Transition issue status
POST   /api/issues/{id}/resident-update — Generate resident update
GET    /api/zone-priorities — Zone-level priority summary
GET    /api/zone-summary    — Zone status overview
POST   /api/issues/{id}/resident-update — AI-generated update
```

### Live Demo

- **URL:** https://townops-skill.vercel.app
- **API Inspector:** https://townops-skill.vercel.app/api-inspector
- **SKILL.md:** https://townops-skill.vercel.app/skill-viewer

## Testing

```bash
# Run the town_ops scenario with validation
nest run scenarios/town_ops.yaml --validate

# Check agent responses in trace output
cat ./traces/town_ops.jsonl | jq '.'
```

## Metrics

The scenario tracks:
- **Success Rate** — % of issues resolved within SLA
- **Mean Latency** — Average time from report to resolution
- **Message Count** — Total inter-agent messages
- **SLA Compliance Rate** — % of issues resolved within severity-based SLA

## License

Apache-2.0 (consistent with NANDA Town)
