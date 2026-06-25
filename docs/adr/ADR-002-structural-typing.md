# ADR-002: Structural Typing for Plugins

**Status:** Accepted  
**Date:** 2026-06-25

## Context

Plugin authors use diverse codebases and cannot be forced into a single inheritance hierarchy.

## Decision

Layer interfaces are `typing.Protocol` types. Plugins need only match method signatures; no base class required.

## Alternatives Considered

- ABC inheritance — clearer errors but heavier coupling.
- Code generation from IDL — more ceremony than needed for Alpha.

## Consequences

- Flexible duck typing; pyright validates at author side.
- Runtime signature mismatches possible if types are wrong.

## Risks

IDE support varies; strict pyright required in CI.

## Rollback

Optional mixin base classes without removing Protocols.
