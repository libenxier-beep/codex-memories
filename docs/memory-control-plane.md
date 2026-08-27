# Memory Control Plane V1

## Purpose

Turn memory distillation and application from a prose-only convention into one fail-closed local protocol while retaining Markdown/Git authority and the existing exact-committed knowledge reader.

## Public workflow

```text
prepare -> assess -> candidate-set -> authorize -> apply-workspace -> inspect
                                   \-> recover
```

`prepare` runs deterministic pre-persistence safety checks, validates the bounded candidate/gate contract, verifies local provenance where possible, captures repository/base/worktree/target preconditions, and creates a content-addressed quarantined ledger. Hard gates precede positive scoring and cannot be offset by score. Candidate lookup plus first/new transition runs under one thread-and-process writer critical section; concurrent or later screening of identical content with any failed or unknown hard gate therefore monotonically revokes or precedes a pass. Unsafe gate failures retain only a sanitized content-hash rejection marker, never the raw candidate.

Assessment keeps the compatibility field `total`, but its value is the
effective score: recurrence + transferability + stability + impact +
`(2 - contamination_risk)`. Receipts also expose `positive_total`,
`contamination_risk`, and `effective_total` explicitly. Increasing risk can
therefore never improve eligibility, while the existing 0–10 range and
threshold of 5 remain unchanged.

`assess` accepts the established five 0–2 dimensions only for candidates that passed every hard gate. `candidate-set` freezes one or more candidate hashes. `authorize` requires explicit current-turn evidence for exact IDs or an exact set digest with explicit exceptions. Silence is not authorization. V1 authorization may leave exactly one executable candidate approved; a larger approved subset fails before approval persistence with `batch_application_unsupported` because V1 has no atomic multi-target apply.

`apply-workspace` rechecks every binding and the candidate validity window, rejects untracked/ignored authority plus hidden or unmerged index state anywhere in the bound repository snapshot, renders the full tracked post-state in an isolated local clone, materializes submodules at the exact parent `HEAD` gitlinks rather than staged gitlink entries, generates a prospective Ring 0 adapter, and runs fixed validators before the real target changes. It then seals a complete expected post-workspace digest in the intent, opens the authority parent component-by-component with `O_NOFOLLOW`, and performs the final precondition, rename, post-read, and directory fsync relative to the retained parent descriptor. The resulting receipt is identified over its complete semantic body and must exactly match candidate, approval, intent, and ledger-event evidence. It never stages, commits, pushes, publishes, or deploys.

An applied `add` remains an untracked working-tree file because publication is outside this module. While any untracked file exists under an allowlisted authority subtree, later `prepare` calls fail before candidate persistence with `unpublished_authority_state`. An external exact-path Git operation must first make that authority state trackable; the control plane never performs that operation or labels it publication.

## Status vocabulary

- Candidate disposition: `quarantined | needs_confirmation | rejected | approved`.
- Workspace progress is evidenced by events and receipts, not mixed into candidate disposition.
- `workspace_applied` is the strongest P0 result.
- `published`, `committed_reader_visible`, and `active_for_committed_recall` require an authorized Git publication plus exact committed read-back; P0 cannot produce them.
- `expired` and eligibility are derived at read time, not stored as a scheduler-dependent state.

## P0 operations

`add`, `update`, and `no_op` are supported. Merge, split, routing, supersession, and deprecation are proposal decisions that compile to a supported primitive. `delete` is rejected as `unsupported_operation` until P1 tombstone-aware recall prevents resurrection.

## Authorization claim

The module has no host-issued identity capability. It therefore records `authorization_strength: honest_client_audit` and `host_authenticated: false`. The calling Skill must only create approval evidence after explicit current-turn user authorization. A future protected host capability can strengthen this boundary; local hashes alone cannot.

## Recovery

Ledger/artifact updates pin every control directory with `openat`/`O_NOFOLLOW`, then use dir-fd-relative bounded reads, temporary writes, fsync, atomic replace, and directory fsync. Authority replacement uses the same descriptor-relative discipline for the retained destination parent. An intact intent plus the exact target-after state and complete post-workspace digest can be finalized without a second authority write. Receipt issuance is recorded in the candidate event before the receipt projection, making a crash between those stages replayable with the same `receipt_id`, `recovered`, and `completed_at`. Recovery rechecks approval linkage, validity time, base/branch/worktree identity, provenance, repository-wide unsafe index state, untracked authority, and the complete post-state before issuing a receipt. The expected before digest remains resumable. A third digest, broken chain, unknown artifact, stale approval/source/base/workspace/target, or non-equivalent receipt fails closed.

Approval receipt creation is also retry-safe: if execution stops after the content-bound receipt is durable but before the candidate ledger is linked, the same exact authorization reconciles the missing ledger event. A conflicting authorization still fails closed.

The configured control root, writer lock, and fixed `candidates`, `approvals`, `intents`, and `receipts` directories are opened component by component without following symlinks. Reads and atomic replacement stay relative to retained directory descriptors, so swapping a checked pathname cannot redirect control evidence outside the repository.

## Recall boundary

`scripts/knowledge_access.py` remains the public recall seam. `control_plane/` is not included in recall. Working-tree policy recall is labeled `authority: working_tree_layer` and `committed: false`; configured-layer symlinks cannot escape their layer, and aggregate path/file/byte budgets stop traversal before unbounded work. Public `history`, `recent`, and `evidence` modes default-deny without enumerating files; V1 exposes no caller-self-asserted bypass while a trusted host capability is unavailable. Any later index is disposable and subordinate: it must filter privacy, scope, lifecycle, time, trust, and tombstones before use, then reopen the canonical source and verify its digest.

The P1 implementation is `scripts/memory_projection.py`. It builds only from exact Git blobs under `core/`, `platform/`, and `learnings/`; it never scans `personal_knowledge/`, `personal_memories/`, or `control_plane/`. FTS5 is probed at runtime. If unavailable, the backend is explicitly reported as `sqlite_bounded_lexical`; neither backend is called semantic search. Rebuild equivalence uses a sorted logical manifest digest rather than raw SQLite bytes.

The parent Ring 0 knowledge-route projector also treats a Work Context submodule as committed authority: when the mount is a parent `HEAD` gitlink, it reads the registry and active README blobs from that exact child commit. Dirty child-checkout content cannot enter `memory_index.md`.

Committed `lifecycle/tombstones/*.json` overlays are strictly typed, win before ranking, and bind an exact item/path/content digest. SQLite may propose only an item ID: path, digest, scope, lifecycle, time, and returned content are reconstructed from the current committed tree. The stored manifest must match a fresh canonical manifest, query size/token limits run before database open, and both FTS and non-FTS lanes apply canonical eligibility before an item can consume the bounded candidate budget. The supported non-FTS backend scans IDs incrementally, matches against canonical content, and retains only a bounded top-candidate set without truncating the corpus by arbitrary item order. The committed authority corpus itself is capped at 10,000 items and 64 MiB; exceeding either budget fails explicitly as `authority_budget_exceeded`. Retention is dry-run only, recomputes current committed authority instead of trusting mutable rows, uses item metadata rather than invented global TTL constants, and never promises Git-history erasure.

## Threat model

The control plane protects against mistakes, stale state, partial local writes, malformed or unsafe candidate content, mutable projection data, and concurrent honest-client operations. Git runs through an absolute trusted executable with a minimal environment, replacement refs and ambient config disabled. Production validator commands are fixed by tracked code; stdout is streamed into a hard byte budget and the process is terminated at the limit. The candidate binds the complete tracked-workspace digest used for prospective validation, the unsafe-index inventory covers the same repository-wide tracked path set, and the intent binds the complete verified post-state. A local principal able to rewrite the implementation, validator code, Git objects, and control artifacts and then recompute every digest is outside this V1 trust model; receipts explicitly do not claim cryptographic user authentication or resistance to a fully compromised local account.

## Commands

```bash
python3 scripts/memory_control.py prepare --candidate - --gates gates.json
python3 scripts/memory_control.py assess --proposal cand_... --assessment assessment.json
python3 scripts/memory_control.py candidate-set cand_... cand_...
python3 scripts/memory_control.py authorize --set-digest ... --evidence approval.json
python3 scripts/memory_control.py apply-workspace --proposal cand_... --approval appr_...
python3 scripts/memory_control.py inspect --proposal cand_...
python3 scripts/memory_control.py inspect --audit
python3 scripts/memory_control.py recover
python3 scripts/memory_projection.py build
python3 scripts/memory_projection.py recall "deterministic review" --scope global
python3 scripts/memory_projection.py manifest
python3 scripts/memory_projection.py retention-plan --as-of 2026-08-12T00:00:00Z
```

All commands return JSON. Error output uses stable machine codes and must not echo unsafe candidate contents. Every JSON file or stdin transport is bounded before decoding; candidate metadata also has aggregate, list-cardinality, and string budgets.
Prefer bounded stdin for `prepare --candidate -`; do not materialize the full draft as a command argument.
