# ADR-005: Entry-Point Plugin Discovery

**Status:** Accepted  
**Date:** 2026-06-25

## Context

Third-party plugins install via pip and must be discoverable without editing Nanda Town source.

## Decision

- Plugins register under `nest.plugins.<layer>` entry point groups in `pyproject.toml`.
- [`PluginRegistry`](../../packages/nest-core/nest_core/plugins.py) discovers via `importlib.metadata` and falls back to built-in reference paths.

## Alternatives Considered

- YAML plugin manifest — extra file to maintain.
- `PYTHONPATH` plugin dirs — not pip-friendly.

## Consequences

- Standard Python packaging; `nest plugins list` shows available plugins.

## Risks

Name collisions across distributions.

## Rollback

Require namespaced plugin names (e.g. `vendor_scheme`).
