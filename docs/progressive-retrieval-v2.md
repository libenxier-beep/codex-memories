# Progressive Retrieval v2

This runtime can let the current Codex model drive a bounded local memory
retrieval loop. It does not start a second model and does not upload the
memory corpus to another service.

The `UserPromptSubmit` hook performs the first governed retrieval round. It
injects only Git-reopened evidence and an owner-generated session token. If
that evidence is sufficient, Codex answers normally and no further retrieval
round is needed. If it is insufficient, Codex may use the rendered local
`progressive show` and `progressive step` commands for at most three rounds.

Activation is explicit and reversible:

```bash
/usr/bin/python3 scripts/agent_memory.py \
  --progressive-state-dir /absolute/owner-only/state \
  progressive enable

/usr/bin/python3 scripts/agent_memory.py \
  --progressive-state-dir /absolute/owner-only/state \
  progressive rollback
```

Session files are mode `0600`. Active sessions retain the current query only
for replay and are removed after 24 hours; completed sessions remove the query
immediately. Retrieved text remains untrusted evidence and cannot mint host
authorization handles.

The runtime binding identifies frozen retrieval candidate commit
`cb0761fcc072dac32ac20a493aa85bb46deab9e8` and tree
`6c38ceedebce016ddd57829327b8898d20324530`.
