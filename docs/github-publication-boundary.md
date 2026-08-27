# GitHub Publication Boundary

This repository branch is a sanitized source projection of the Memory Control Plane. It contains architecture, policy code, schemas, tests, and operational documentation only.

The allowlisted source projection may include the local-only Agent Memory
runtime and synthetic production tests. Historical blind Harness generations,
checker outputs, runtime databases, and sealed evaluation artifacts are not
part of the deployable source surface.

The projection deliberately excludes:

- personal knowledge and user-profile material;
- Work Context corpus content;
- candidate, approval, intent, receipt, and lock state;
- raw evidence, session data, generated indexes, caches, and backups;
- machine-local paths, credentials, tokens, and private identifiers.

These exclusions are part of the publication contract, even when the GitHub repository is private. Local deployments may attach their own private authority and validators, but those assets are not synchronized by this branch.

The committed test fixtures use only synthetic values such as `example.invalid` addresses and intentionally non-secret token-shaped strings.
