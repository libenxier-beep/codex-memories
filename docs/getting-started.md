# Getting Started

This guide takes a clean machine from clone to an inspectable Codex Memories
deployment. The installer never uploads memory data and never mutates Codex hook
configuration.

## 1. Install

Requirements: Python 3.9+, Git, and enough local disk space for a small SQLite
sidecar.

```bash
git clone https://github.com/libenxier-beep/codex-memories.git
cd codex-memories
./install.sh
```

To use custom locations:

```bash
./install.sh \
  --prefix /absolute/path/to/codex-memories \
  --authority /absolute/path/to/private-memory-authority \
  --codex-home /absolute/path/to/codex-home
```

`--prefix` and `--authority` must be separate. Re-running the installer updates
the runtime copy and preserves the private authority. Pass `--skip-index` when
you want to build the first index later.

## 2. Verify the deployment

```bash
~/.local/share/codex-memories/bin/codex-memories doctor
```

`ready` means the runtime, launcher, private Git authority, and merge plan are
intact. `integration: review_required` is expected before the hook plan is
applied.

## 3. Review the hook plan

Open `~/.local/share/codex-memories/hooks.merge-plan.json`. It contains:

- hashes of the original and proposed configuration;
- the complete proposed `hooks.json` document;
- the exact events added by Codex Memories;
- the absolute, policy-bound command that will handle each event.

Do not replace a governed `hooks.json` blindly. Have its configuration owner
merge the `merged` document, update any external trust digest, and preserve all
existing hooks. Running `doctor` again reports `integration: active` only when
the current document matches the reviewed plan.

## 4. Try recall directly

```bash
~/.local/share/codex-memories/bin/codex-memories index
~/.local/share/codex-memories/bin/codex-memories recall "governed local memory"
~/.local/share/codex-memories/bin/codex-memories health
```

A fresh authority contains one starter record at `core/welcome.md`. Replace it
with durable rules that follow `memory_schema.md`, commit them to the private
authority, and rebuild the index. Existing non-empty authorities are preserved
and must already be Git repositories.

## Upgrade

Pull a reviewed release in the source clone and run `./install.sh` again with
the same paths. The runtime copy and hook plan are refreshed; private authority
files and sidecar data stay in place. Review the new hook-plan digest before
applying configuration changes.

## Rollback and removal

Remove the Codex Memories command groups through the owner of `hooks.json` first.
The installed runtime directory can then be removed independently. Keep the
authority directory if you want to retain durable memories; keep or delete the
sidecar independently because it is rebuildable and is never authority.

## Troubleshooting

- `authority must be a Git repository`: choose an empty directory or initialize
  and commit the existing authority first.
- `integration: review_required`: the generated hook plan has not been applied,
  or the current configuration differs from the reviewed plan.
- `semantic_status: degraded`: local embeddings are unavailable. Lexical recall
  remains available; macOS can use the bundled Swift NaturalLanguage helper.
- `recall_policy_missing`: use the installed launcher, which binds the built-in
  `local-work` policy, or pass an explicit RecallPolicy to the low-level CLI.
