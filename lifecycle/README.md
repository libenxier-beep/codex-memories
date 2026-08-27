# Memory Lifecycle Overlays

`tombstones/` is the canonical P1 overlay for preventing an exact standalone item version from returning through the disposable memory projection.

A tombstone binds stable item ID, authority path, exact authority digest, approval receipt, reason, and creation time. It takes precedence before ranking and return. A stale tombstone does not suppress a genuinely changed authority digest. Malformed tombstones fail projection rebuild closed.

Tombstones are meaningful only as reviewed Git authority. A local uncommitted file is not described as published deletion. They do not erase Git history, do not apply item-level deletion semantics to aggregate Ring 0 handbooks, and are not written automatically by retention planning.

`scripts/memory_projection.py retention-plan` is deterministic and dry-run only. It proposes review or a future tombstone candidate; it never purges content.
