# Memory Schema

## Purpose

- Define how durable memory items should be written, classified, reviewed, downgraded, and retired.

## Required Fields

- `id`: stable identifier
- `title`: short human-readable title
- `summary`: one-sentence description
- `scope`: `global | runtime | platform | repo | learning`
- `applies_to`: `all | codex | claude_code | openclaw`
- `type`: `principle | preference | procedure | config | skill | learning`
- `stability`: `high | medium | low`
- `authorization_state`: `not_required | user_approved`
- `provenance_trust`: `canonical_legacy | current_source_validated | source_bound_candidate`
- `privacy_class`: `public | private_local`
- `source`: where the item came from
- `evidence`: why it is trusted enough to keep
- `regression_risk`: `low | medium | high`
- `supersedes`: prior item ids or file references
- `last_reviewed`: `YYYY-MM-DD`
- `owner`: who maintains it

## Recommended Extra Fields

- `status`: `active | candidate | superseded | deprecated | legacy`
- `sync`: notes for Codex, Claude Code, and OpenClaw adapter handling

## Frontmatter Template

```md
---
id: example-id
title: Example Title
summary: One-sentence summary.
scope: global
applies_to: all
type: principle
stability: high
authorization_state: user_approved
provenance_trust: current_source_validated
privacy_class: private_local
source:
  - study_resource_or_review
evidence:
  - reason this is worth keeping
regression_risk: medium
supersedes: []
last_reviewed: 2026-03-09
owner: memory-maintainer
status: active
sync:
  codex: yes
  claude_code: yes
  openclaw: yes
---
```

## Governance Metadata Rules

- For a new hand-authored private-local item, use `user_approved + current_source_validated + private_local` only after the user explicitly approves that item for durable recall.
- For a new low-sensitivity item intentionally available to public recall, use `not_required + current_source_validated + public`.
- Reserve `source_bound_candidate` for control-plane output with a verifiable source binding.
- Keep `canonical_legacy` as a compatibility classification for reviewed legacy authority; do not use it as the default for new items.
- Omitting any governance field invokes legacy compatibility defaults and may make an item unreachable through built-in recall policies. New hand-authored authority must set all three fields explicitly.
- Never label an item `public` merely to make it recallable.

## Body Sections

Each durable item should answer:

1. `What`: what the item says
2. `Why`: why it is worth keeping
3. `When To Apply`: trigger conditions
4. `When Not To Apply`: scope limits or anti-patterns
5. `Sync Notes`: whether and how it maps to platform adapters
6. `Review / Downgrade Conditions`: when to update, lower scope, or retire it

## Intake Rules

- Only keep items that improve future judgment, execution, reliability, or collaboration fit.
- Reject one-off context, unstable guesses, machine-local details, and project-only constraints from the global layer.
- If an item is only valid for one platform, mark `scope: platform`.
- If an item is short-lived or active-task specific, keep it in the runtime sidecar or a rollout retrospective instead of durable memory.
- Before committing a hand-authored item, verify that its governance metadata matches the intended built-in recall policy. Missing metadata does not imply approval.

## Downgrade And Retirement Rules

- Downgrade `global` to `platform` when the rule depends on agent-specific behavior.
- Downgrade `global` or `runtime` to `repo` when the rule only matters in one repository.
- Downgrade or relocate to the runtime sidecar when the item reflects temporary state rather than durable judgment.
- Mark `superseded` instead of deleting when a better formulation replaces an older one.
- Mark `deprecated` when an item stops being useful and no replacement is needed.
