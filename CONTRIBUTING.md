# Contributing

Focused issues and pull requests are welcome. This repository publishes runtime
code and synthetic evidence only; never include real memories, local paths,
runtime databases, credentials, private identifiers, or hidden evaluation data.

## Development loop

```bash
git clone https://github.com/libenxier-beep/codex-memories.git
cd codex-memories
python3 -m unittest discover -s tests
```

Use a `codex/<topic>` branch for one bounded change. Add tests through a public
CLI or module seam, run the smallest relevant test during development, then run
the complete suite and `git diff --check` before requesting review.

Good contributions include reproducible retrieval cases, safer onboarding,
cross-platform diagnostics, lifecycle failures, and documentation corrections.
Quality comparisons must report denominators, failures, latency/cost conditions,
and rejected runs—not only favorable headline numbers.

Security vulnerabilities should follow [SECURITY.md](SECURITY.md), not a public
issue.
