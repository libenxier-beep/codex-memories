# Memory Control Plane Artifacts

This directory is the declared owner for local memory proposal ledgers, approval evidence, workspace-application intents, and receipts.

## Authority

- The owning Markdown files and Git history remain durable memory authority.
- A candidate ledger is quarantined control evidence, never active memory and never a recall source.
- `workspace_applied` means that fixed validators passed against an isolated post-state, the exact authorized bytes were applied, and the complete live post-workspace digest matched the sealed intent. It does not mean Git commit, publication, deployment, or visibility through an exact-committed reader.
- After an `add`, later candidates are blocked with `unpublished_authority_state` until an external exact-path Git operation makes the new authority file trackable. The control plane never stages it automatically.
- Hash chains and artifact hashes detect accidental or inconsistent modification. They do not authenticate the user or resist an attacker who can rewrite local files and recompute hashes.
- V1 approval can authorize exactly one executable candidate. Multi-candidate application is rejected before approval persistence because there is no atomic multi-target transaction.

## Layout

- `candidates/cand_<sha256>.md`: immutable normalized proposal plus append-oriented event chain.
- `approvals/appr_<sha256>.md`: explicit-ID or explicit-set authorization evidence using the honest-client protocol.
- `intents/cand_<sha256>.md`: content-bound target post-state, complete workspace post-state, precondition, and prospective validation evidence written before workspace mutation.
- `receipts/cand_<sha256>.md`: closed-shape, complete-body receipt whose semantic fields and issuance metadata are reconciled against candidate, approval, intent, and event evidence after workspace application.
- `.writer.lock`: runtime advisory lock; it is not a memory source.

Only `README.md` is repository source code by default. Runtime artifacts are created deliberately by `scripts/memory_control.py`; they are not automatically staged or committed.

## Safety

Secret, credential, disallowed private, path-unsafe, prompt-injection, hidden-control, executable-payload, and oversize candidates are screened before raw payload persistence. Candidate identity lookup and every first/new transition are serialized across threads and processes, so a concurrent or later failed hard gate monotonically wins over a pass. A sanitized content-hash rejection marker may preserve that terminal decision, but unsafe rejected raw content must not appear anywhere under this directory. Candidate content never supplies commands, validators, roots, or publication behavior.

The CLI accepts the candidate through bounded stdin (`prepare --candidate -`) so an extra raw candidate transport file is unnecessary; every JSON file path is also size-bounded before decoding. Gate-declared prompt-injection or executable-payload failure also rejects before a new ledger is persisted.

Every fixed artifact directory is opened without following symlinks and retained as a directory descriptor for bounded reads and atomic replacement. Runtime artifacts are limited to 2 MiB each.

`delete` is unsupported in P0. It may be admitted only after a canonical tombstone overlay is enforced by every eligible recall path.
