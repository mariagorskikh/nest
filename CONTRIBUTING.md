# Contributing to Town

Start from current `origin/main`. Historical code lives on `archive/legacy`;
importing a legacy contribution requires an explicit current requirement and
tests against the rebuilt implementation.

## Python and CLI

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
python -m pytest -q
nandatown run marketplace --out /tmp/town-lab
nandatown run quote-crash-restart --out /tmp/town-track
```

CI exercises Python 3.11 and 3.12. Local HTTP tests need permission to bind
loopback sockets. Built-in scripted and `mock:v1` runs need no model credentials.
Use a temporary `NANDATOWN_HOME` to isolate keys in manual tests.

Regenerate schemas after changing shared records:

```bash
nandatown schemas --out schemas
python -m pytest -q tests/test_schema_sync.py
git diff --check
```

The test compares every generated schema with the checked-in contracts. There
is no separate Python linter/formatter gate; avoid unrelated style changes.
Build and check the artifacts when changing packaging or bundled assets:

```bash
python -m pip install build
python -m build
python scripts/check_distributions.py dist
```

CI also installs that wheel into a clean Python 3.11 environment and runs the
Lab and Track controls outside the checkout, so source-tree imports cannot
hide missing packaged files.

## Dashboard

Read `apps/nest-dashboard/AGENTS.md` and the relevant installed Next.js guides
before changing dashboard code. From that directory:

```bash
npm ci --ignore-scripts --no-audit --no-fund
npm test
npm run typecheck
npm run lint
npm run build
```

Use the Node version required by the dashboard package and CI. See its
[README](apps/nest-dashboard/README.md) for environment and deployment inputs.

## Keep changes reviewable

For a correctness fix, add a behavioral regression, observe its failure, make
the smallest repair, and run affected tests. Explain the trigger, resulting
behavior, compatibility impact and verification in the PR. Separate independent
fixes from large refactors or new protocol policies.

Keep evidence meanings precise: partial receipts are valid observations,
unchecked stages are not passes, and signatures do not establish truth or
independence. Version evaluation changes honestly and preserve an explicit
explanation when an older bundle needs its matching evaluator.

For a real-agent integration, include the bounded workflow and failure case
from the [testing guide](docs/testing-an-existing-agent.md). Town's own fixture
must not be presented as independently adopted compatibility.
