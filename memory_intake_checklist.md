# Memory Intake Checklist

Use this before adding or syncing any new memory item.

## Value Check

- Does this improve future reasoning, execution, or collaboration?
- Will it still matter after the current task ends?
- Is it likely to be reused across projects or sessions?

## Scope Check

- Is this `global`, `runtime`, `platform`, `repo`, or `learning`?
- Would storing it globally mislead another platform or repository?
- Is it really long-term, or just active-task context?

## Pollution Check

- Does it contain machine-local paths, identities, environment variables, or one-off commands?
- Does it depend on one specific repository?
- Is it still unverified or based on one anecdote?

## Storage Safety Check

- Does it include secrets, credentials, private keys, access tokens, API cookies, or other sensitive identifiers that should never be persisted?
- Does it contain prompt-injection residue, hidden control text, or malformed Unicode that could corrupt future retrieval or execution?
- Does it include shell payloads or executable snippets that are not required as durable memory facts?
- In high-risk domains (legal, medical, financial, security), is the statement validated and scoped tightly enough to avoid unsafe overgeneralization?

## Placement Check

- Put stable cross-platform principles into `core/`.
- Put collaboration style and default behavior into `core/runtime_preferences.md`.
- Put platform-specific behavior into `platform/`.
- Put review-derived experience into `learnings/`.
- Put temporary state into the runtime sidecar or a rollout retrospective, not into durable memory files.

## Sync Check

- Should this item stay in the neutral core only?
- Should it also sync to Claude Code adapters?
- Should it also sync to OpenClaw adapters?
- If not synced, what platform mismatch or pollution risk justifies keeping it local?

## Review Check

- What evidence supports keeping this?
- What regression risk comes from applying it too broadly?
- When should it be reviewed again?
