---
schema_version: 1
repository_id: codex-memory-runtime
kind: source-runtime
lifecycle: active
criticality: core
owner: liben+codex
last_reviewed: 2026-08-21
---

# Codex Memory Runtime Repository Contract

## Purpose

This repository is the sanitized GitHub source for the Memory Control Plane and
Codex Agent Memory runtime. It publishes deployable code, schemas, architecture,
and synthetic tests. It is not the authority for a user's memories or private
knowledge corpus.

## Publication Boundary

The repository is allowlist-oriented. Personal knowledge, user or agent
profiles, Work Context content, task histories, raw evidence, runtime databases,
generated indexes, caches, backups, credentials, machine-local paths, and
private identifiers must not be committed on any branch. The boundary applies
even when the GitHub repository is private. See
`docs/github-publication-boundary.md` for the complete contract.

## Authority

Production code under `scripts/`, machine contracts under `schemas/`, synthetic
tests under `tests/`, and their supporting documentation are canonical within
this repository. A local deployment supplies and governs its own private
authority sources and validators; those sources must remain outside this Git
remote.

## Branch Policy

`main` is the only long-lived branch and must remain deployable. Use
`codex/<topic>` for one bounded change at a time, then merge and delete the topic
branch and its worktree. Do not use process-state names such as `final`, versioned
test-run branches, or date-only names as permanent lines of development. Every
branch pushed to GitHub must satisfy the publication boundary before review.

## Path Roles

| Path | Role |
| --- | --- |
| `scripts/` | Deployable runtime and control-plane implementation |
| `schemas/` | Machine-readable input, receipt, and lifecycle contracts |
| `tests/` | Synthetic regression and governance tests |
| `docs/` | Architecture, operation, and publication contracts |
| `control_plane/` | Source documentation only; runtime state is ignored |
| `lifecycle/` | Tombstone and retention lifecycle contract |

## Change Gate

Before merging to `main`, run the smallest relevant tests plus `git diff
--check`; privacy-boundary or release changes also require the full documented
validation command. A release is complete only after `main` is updated and the
topic branch and temporary worktree are removed.

## Retirement

Retirement requires a verified replacement, migrated runtime consumers, and a
documented decision for schemas and audit-compatible lifecycle behavior. Private
authority data is never part of retirement or migration from this repository.
