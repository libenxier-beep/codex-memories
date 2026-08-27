# Codex Agent Memory Hook Protocol

This adapter performs no network calls itself and never sends transcript or
embedding material to a remote service. Its `additionalContext` becomes Codex
model input, so private-local authority is default-deny at the hook boundary;
only an explicit bounded task policy may admit an authorized class. The
adapter does not promote candidates or treat a retrieval index as authority.

## Codex events

`scripts/agent_memory_system/hooks.py` accepts one JSON object on stdin and
emits at most one JSON object on stdout.

| Event | Required input | Ordered action | Output |
| --- | --- | --- | --- |
| `SessionStart` | `session_id`, `cwd`; optional non-empty `transcript_path`; host may set `source=compact` | requeue/dispatch stalled work, backfill eligible evidence missed by an older candidate runtime, and repair rebuildable stale indexes; capture a transcript tail only when supplied; reopen the exact current task snapshot | bounded current-task `additionalContext` only when every raw evidence ref verifies |
| `UserPromptSubmit` | common fields plus `prompt`; optional `turn_id` and `transcript_path` | capture the transcript tail when available, otherwise atomically capture the prompt event by `turn_id`; then recall against the current prompt | bounded `hookSpecificOutput.additionalContext` only when governed results exist |
| `PreToolUse` | common fields plus `tool_use_id`, `tool_name`, JSON `tool_input`; optional `turn_id` | atomically capture the tool call by host call ID | none |
| `PostToolUse` | common fields plus `tool_use_id`, `tool_name`, JSON `tool_response`; optional `turn_id` | atomically capture the matching tool result, then transactionally update the current task Offload graph | none |
| `Stop` | common fields plus `last_assistant_message`; optional `turn_id` | atomically capture the final assistant observation; queue candidate formation only for a deterministic lesson backed by a complete same-turn tool pair | none |
| `SessionEnd` | `session_id`, `cwd`; optional `transcript_path` | flush the transcript tail when the host supplies one; otherwise finish without inventing evidence | none |

Failures are fail-closed: the adapter asks the runtime to record a bounded
pipeline error and writes nothing to stdout. It returns success to Codex so a
memory-sidecar outage does not break the user's task.

## Runtime callback seam

`CodexHookAdapter` accepts a runtime implementing nine callbacks:

```python
capture_incremental(session_id, transcript_path, cwd, flush)
capture_prompt(session_id, prompt, cwd, source_event_id)
capture_tool_call(session_id, cwd, turn_id, tool_use_id, tool_name, tool_input)
capture_tool_result(session_id, cwd, turn_id, tool_use_id, tool_name, tool_response)
capture_assistant(session_id, cwd, turn_id, content)
recall_governed(query, cwd, session_id)
recover(session_id)
offload_context(session_id, cwd)
record_pipeline_error(stage, code, detail, source_ref=None)
```

Capture owns event idempotency and transcript checkpoints. A real Codex
`UserPromptSubmit` currently carries `transcript_path: null` and a stable
`turn_id`; the private store therefore records that prompt directly as
`codex-hook://UserPromptSubmit` evidence and queues an exact distill job. A
retry with the same `turn_id` is a duplicate, while a new turn remains a new
observation. `PreToolUse` and `PostToolUse` use the real host `tool_use_id` as
their replay identity. A durable cursor reads only new evidence, pairs callbacks
across restarts, and records an exact-once receipt; malformed or unmatched
records enter the DLQ without blocking later pairs. A matching pair creates one
versioned Offload step whose automatic state is a closed `ToolOutcome v1`:
tool identifier, enumerated status/error code, finite numeric metrics, and an
opaque evidence ref. Raw tool arguments/results, commands, JSON strings, logs,
Markdown, HTML, and code are never automatic context. Explicit drill-down
retains the minimized raw bytes and verifies hash, session, task, creation
version, step, and source ref. `Stop` records the
assistant message under the turn identity. Ordinary assistant prose stays
evidence-only. A deterministic lesson may enter the candidate quarantine only
when the same turn reopens a complete tool call and result; its governed
proposal cites the assistant span plus a bounded set of the most recent complete
supporting pairs and still cannot authorize or publish itself. Recall requires
the same closed `RecallPolicy v1` used by direct projection, hybrid retrieval,
and knowledge access. Missing or malformed policy abstains, and canonical
reopening owns all scope, time, lifecycle, authorization, provenance, privacy,
tombstone, deleted, source revision/hash, and relevance checks. The hook adapter enforces a second rendering
gate: a record is injectable only when `authority_reopened is True`,
`governance == "pass"`, and non-empty `content`, `source_ref`, and
`authority_revision` are present.

The hybrid index is not bound to one request policy. It admits only structurally
safe committed authority under `stable_committed_authority_v1`; dynamic scope,
platform, time, authorization, provenance, privacy, and query classification are
applied before candidate ranking and again during canonical reopen. The optional
`--recall-policy-profile local-work` is a versioned built-in deployment policy
for this single-user runtime. It resolves `as_of` at each process start and
permits only `user_approved` public/private-local work memory with validated or
source-bound provenance. Explicit policy files remain available for deterministic
administration and evaluation.

When a host supplies `transcript_path`, the hook runtime accepts it only beneath
an explicitly configured `--transcript-root`, requires the session ID in the
regular filename, resolves containment before use, and opens the final path with
no-follow semantics. Hook-controlled paths cannot select an arbitrary JSONL or
another session. Direct administrator `capture` remains a separate explicit CLI
operation. Session, path, cwd, event/tool IDs, messages, JSON objects, and stored
metadata all have independent byte caps in addition to the total hook envelope.

Context is admitted a complete record at a time under closed
`OffloadInjection v2` validation. It is never sliced through a record merely to
fill the budget. Beside it, `TaskInvariant v1` carries only exact user spans for
the task goal, hard constraints, and confirmed decisions. Every item binds the
session, event ID, source span, source hash, and either `user_authority` or
`assistant_advisory`; the production builder currently emits only user
authority and leaves phase/action/blocker advisory fields empty. Raw tool
prose, shell output, web text, logs, prompt-injection clauses, and unverified
tool conclusions are ineligible. The invariant is rebuilt from a bounded
user-only evidence query and reverified after restart. Its rendered budget is
at most 1,200 characters, Offload v2 is at most 1,500, and the complete callback
still remains under the configured 4,000-character default. Durable,
TaskInvariant, and offload validation fail closed without turning one invalid
branch into authority for another.

Codex does not currently accept replacement output for ordinary tools from a
`PostToolUse` hook. The integration therefore does not pretend to erase the
host's current raw result. It persists that result, updates the compact task
graph, and reinjects the verified graph on the next prompt. When Codex performs
its own compaction, the subsequent `SessionStart` with `source=compact` also
reinjects the graph, so constraints and evidence handles survive the context
transition while the host remains responsible for actually dropping old turns.

## Context Offload store seam

`OffloadEngine` accepts a store implementing:

```python
commit_offload_bundle(bundle)
load_offload_task(task_id, version=None)
load_offload_evidence(evidence_ref)
list_offload_versions(task_id)
```

The production runtime separately calls
`list_task_invariant_sources(session_id, limit=32)` on its concrete sidecar
store; that bounded user-only query is not part of the generic Offload engine
protocol.

`commit_offload_bundle` is the transaction boundary. Evidence objects, the new
task snapshot, version/checkpoint, and receipt must all commit or all abort.
Evidence is canonical JSON compressed as deterministic gzip, with its
`sha256:<digest>` as the immutable handle. Task injection and drill-down require
an exact version; the engine never silently substitutes the newest or an older
task. Compaction validates tool-call/result adjacency and raw-ref integrity
before removing original tool bytes. Unpaired or unreferenced tool evidence is
retained with an explicit degraded reason.

All store writes pass one recursive secret-minimization gate before hashing and
persistence. Evidence quota accounting includes identifiers, provenance,
metadata JSON, and content; duplicated offload accounting includes both payload
and its canonical evidence JSON. Evidence, candidates, snapshots, and duplicated raw offload data
have finite TTL and per-session/global count and byte quotas. Health exposes
retained bytes, oldest evidence, quota/purge state, plus offload cursor, lag,
last success, retry queue, and DLQ. A canonical deletion receipt purges its
source-bound runtime sessions in one transaction, tombstones raw restore, and
invalidates rebuildable indexes; its sanitized authority receipt makes retry
idempotent after source evidence has gone. A whole-session purge also installs a
permanent opaque session deletion barrier: new event IDs cannot resurrect that
session, and reopening requires a separately designed authorized new-session
flow rather than an implicit retry.

## Installation boundary

`build_hooks_merge_plan()` deep-copies an existing hooks document, preserves all
existing matchers and commands, and idempotently proposes one command group for
each supported event. The returned object contains the original and prospective
SHA-256 digests plus the full merged document. It is a plan only.

The production hook and real Codex host path are executable and tested in an
isolated `CODEX_HOME`. The live `$CODEX_HOME/hooks.json`, however, may be a
byte-for-byte Environment Governance projection with separately trusted hashes.
Changing it from this repository would transfer configuration responsibility
and invalidate that verifier. Codex 0.148 also reports the former
`plugin_hooks` feature as removed, so a personal plugin cannot safely bypass
that ownership boundary. This repository therefore emits a merge plan but must
not mutate the live hook projection or live `config.toml`. Installation requires a separately
reviewed Environment Governance change that adds the digest-bound Agent Memory
command, updates trust state, and preserves its existing permission hook.
