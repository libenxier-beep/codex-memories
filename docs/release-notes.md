# Codex Memories 0.2.0-preview.1

A local-first memory runtime for Codex, now easier to try before installing.

## Start here

Download and extract the source archive, or clone the repository. With Python
3.9+ and Git installed, run:

```bash
python3 scripts/codex_memories.py demo
```

The demo commits a synthetic decision, builds an index and recalls it in a new
process. It cleans up its temporary deployment without changing your Codex setup.
No API key or account is needed for this local demo.

To install, run `./install.sh` and follow
[Getting Started](https://github.com/libenxier-beep/codex-memories/blob/main/docs/getting-started.md).
Automatic Codex capture and recall require the documented hook integration step.

## What's included

- Disposable first-run demo, also available from the installed launcher.
- Diagnostics with failure exit codes and an optional integration requirement.
- English and Chinese entry points, a first-memory walkthrough and feedback forms.
- Synthetic tests and a public demo check on macOS and Linux before publishing.

## Preview limits

Windows is not yet validated. Configuration checks do not prove live Codex hook
execution. General recall superiority has not been demonstrated; the repository
publishes evaluation limitations. There is no hosted vector database, but recalled
evidence may enter the Codex model context. Keep sensitive data scoped appropriately.

[Report an issue or share first-run feedback](https://github.com/libenxier-beep/codex-memories/issues/new/choose).
