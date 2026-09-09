# Getting Started

This guide takes a clean machine from clone to an inspectable Codex Memories
deployment. The installer never uploads memory data and never mutates Codex hook
configuration.

## Try a disposable demo

Run `python3 scripts/codex_memories.py demo` from the source clone. It uses
synthetic data in a temporary directory and prints `demo: PASS` after a real
index-and-recall check in separate processes. No API key or Codex configuration
is needed. Its temporary deployment is removed on exit, including on failure.
The installed launcher also supports `codex-memories demo`.

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

`doctor` exits with status 1 if the runtime is broken. Use
`doctor --require-integration` to also exit with status 1 while integration is
pending. Exit status 2 indicates a configuration or command error. Configuration
checks cannot prove that your Codex host executed a hook; verify a live session.

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

For a standalone setup, back up any existing `hooks.json`, review the plan's
commands, then save the value of its **`merged` object** as `hooks.json` in your
Codex home (not the whole plan with metadata). It already includes existing
hooks. If your configuration changed since installation, rerun the installer
before merging. If a tool manages or signs your hooks, use that tool's workflow.

Fully quit and reopen Codex after configuring hooks. Event support and trust
configuration depend on your Codex host. CLI recall can also be used independently.

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

## 5. Add your first memory

In your **private authority**, copy `core/welcome.md` to `core/project-decision.md`.
Give it a unique `id`, update the title, summary and `last_reviewed`, and replace
the body with one accurate rule. For a practice example:

```markdown
# Offline task storage

The example Aurora project stores its offline task queue in SQLite.
```

Keep the governance fields from the starter only when they accurately describe
your own reviewed rule. Do not mark unreviewed third-party text as approved.
From the private authority directory, commit only the new file:

```bash
git add core/project-decision.md
git commit -m "Remember offline task storage decision"
~/.local/share/codex-memories/bin/codex-memories index
~/.local/share/codex-memories/bin/codex-memories recall "Aurora offline task queue SQLite"
```

Expected: `ok: true`, `result.status: hit`, and the committed rule in
`result.matches[].evidence`. Configure your Git identity for this private
repository if Git requests it. Never publish the private authority.

## 6. Verify a new Codex session

After configuring hooks, start a fresh session and ask about the saved decision.
Check the answer and source. If CLI recall works but the session does not,
troubleshoot hook configuration rather than adding duplicate memories.
Automatic capture creates candidates; it does not approve every conversation
as durable truth.

[Share first-run feedback](https://github.com/libenxier-beep/codex-memories/issues/new/choose)
using made-up examples. Redact private text and paths from diagnostics.

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
