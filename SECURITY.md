# Security Policy

Codex Memories handles local transcripts and private durable memory. Please do
not publish a vulnerability report that includes real memories, credentials,
machine-local paths, runtime databases, hook payloads, or private identifiers.

Report suspected vulnerabilities through GitHub's private vulnerability
reporting for this repository. Include a minimal synthetic reproduction, the
affected commit, platform and Python version, expected fail-closed behavior, and
the observed impact.

The supported surface is the latest commit on `main`. Security fixes preserve
the publication boundary in `docs/github-publication-boundary.md`; private data
is never requested as proof.
