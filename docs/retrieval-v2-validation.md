# Retrieval v2 Validation Record

This document records aggregate evidence for the progressive retrieval v2
candidate. It deliberately distinguishes public development results from
sealed evaluation and live runtime checks.

## Public synthetic development

The frozen 330-query public development surface reported:

| Measure | Result |
| --- | ---: |
| Planner Recall@5 before/after duplicate-stall repair | 0.8667 / 0.8933 |
| H3 Recall@5, three cold runs | 0.8800 / 0.8867 / 0.8800 |
| No-answer false-positive rate, three runs | 0 / 0 / 0 |
| Minimum English / mixed / Chinese Recall@5 | 0.89 / 0.87 / 0.86 |
| Ordered multihop | 30 / 30 |
| Stale, deleted, privacy, permission, scope, or authority mismatch hits | 0 |

The repair changed duplicate-stall handling. It did not increase Top-K, add a
new index, widen the retrieval budget, or relax the safety threshold. The
campaign's non-sealed regression suite reported 495/495 passing tests.

## Sealed evidence boundary

One compact hidden synthetic seal contained 26 queries, including only six
answerable queries. The candidate retrieved 3/6 answerable items at Top 5,
compared with 5/6 for the one-shot baseline and 6/6 for the narrow Mem0
comparator. Its no-answer false-positive rate was 3/20. The candidate was
correctly rejected on that seal.

A planned independent N=180 Large-B3 evaluation did not execute. Its attempts
stopped before seal creation or candidate scoring because the evaluation
control plane could not satisfy its frozen integrity and execution contracts.
Therefore this repository does **not** claim a Large-B3 pass, a general Mem0
quality match, or validated performance on private memories.

The recorded remote-evaluation ledger at the end of that campaign was 2,347
model calls and approximately USD 39.05. These were benchmark-development
calls, not normal runtime usage.

## Published runtime verification

The public repository contains the executable unit and integration tests for
the control plane, Codex hooks, progressive loop, host authorization, and
answerability verifier. The publication candidate passed 270/270 tests. Run
all of them with:

```bash
python3 -m unittest discover -s tests
```

The live integration release also passed a local end-to-end hook smoke: a
`UserPromptSubmit` event produced a candidate-bound progressive control block
and Git-reopened synthetic/work-domain evidence through the stable runtime
entrypoint. No extra model was launched by the memory runtime.

## Publication exclusions

Raw private authority, Work Context content, consumed seals, hidden qrels,
session transcripts, per-query model outputs, local paths, and historical
control-plane failure artifacts are excluded. Their absence is a privacy and
evaluation-integrity property, not evidence that those evaluations passed.
