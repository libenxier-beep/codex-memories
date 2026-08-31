from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
import sqlite3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from agent_memory_system.retrieval import GovernedHybridRetrieval  # noqa: E402
from agent_memory_system.embedding import (  # noqa: E402
    EmbeddingUnavailable,
    LocalNaturalLanguageEmbedding,
)
from memory_control_plane.projection import MemoryProjection  # noqa: E402
from memory_control_plane.recall_policy import RecallPolicy  # noqa: E402


def recall_policy(scopes: list[str], *, private_profile: bool = False) -> RecallPolicy:
    return RecallPolicy.from_mapping(
        {
            "schema_version": 1,
            "scopes": scopes,
            "applies_to": "all",
            "as_of": "2026-08-19T00:00:00Z",
            "allowed_authorization_states": ["not_required", "user_approved"],
            "allowed_provenance_trust": ["canonical_legacy", "current_source_validated"],
            "allowed_privacy_classes": ["public"],
            "high_stakes": False,
            "private_profile": private_profile,
            "eligible_lifecycles": ["active", "legacy"],
            "require_source_revision_match": True,
            "require_content_hash_match": True,
            "require_canonical_relevance": True,
            "exclude_tombstoned": True,
            "exclude_deleted": True,
        }
    )


def local_work_policy(scopes: list[str]) -> RecallPolicy:
    return RecallPolicy.from_mapping(
        {
            "schema_version": 1,
            "scopes": scopes,
            "applies_to": "all",
            "as_of": "2026-08-19T00:00:00Z",
            "allowed_authorization_states": ["user_approved"],
            "allowed_provenance_trust": [
                "current_source_validated",
                "source_bound_candidate",
            ],
            "allowed_privacy_classes": ["public", "private_local"],
            "high_stakes": False,
            "private_profile": True,
            "eligible_lifecycles": ["active", "legacy"],
            "require_source_revision_match": True,
            "require_content_hash_match": True,
            "require_canonical_relevance": True,
            "exclude_tombstoned": True,
            "exclude_deleted": True,
        }
    )


class DeterministicSemanticEmbedding:
    """A real test adapter for the embedding provider seam, not an internal mock."""

    def describe(self):
        return {
            "status": "ready",
            "provider": "deterministic-test",
            "model": "heldout-fixture-v1",
            "dimension": 3,
            "fingerprint": "test-fixture-v1",
            "privacy": "local_only",
        }

    def embed(self, texts):
        vectors = []
        for text in texts:
            folded = text.casefold()
            if "resume stalled background work" in folded or "流水线停滞" in text or "检查点恢复" in text:
                vectors.append([1.0, 0.0, 0.0])
            elif "授权" in text:
                vectors.append([0.0, 1.0, 0.0])
            else:
                vectors.append([0.0, 0.0, 1.0])
        return vectors


class SizeBoundSemanticEmbedding:
    """Provider seam that enforces the production per-text byte contract."""

    MAX_TEXT_BYTES = 64 * 1024

    def __init__(self) -> None:
        self.seen_sizes: list[int] = []
        self.seen_batch_sizes: list[int] = []

    def describe(self):
        return {
            "status": "ready",
            "provider": "size-bound-test",
            "model": "size-bound-v1",
            "dimension": 2,
            "fingerprint": "size-bound-v1",
            "privacy": "local_only",
            "network": False,
        }

    def embed(self, texts):
        sizes = [len(text.encode("utf-8")) for text in texts]
        self.seen_sizes.extend(sizes)
        self.seen_batch_sizes.append(sum(sizes))
        if any(size > self.MAX_TEXT_BYTES for size in sizes):
            raise ValueError("embedding text exceeds size limit")
        if sum(sizes) > 2 * 1024 * 1024:
            raise ValueError("embedding batch exceeds size limit")
        return [
            [1.0, 0.0]
            if "remote semantic concept" in text.casefold()
            or "ORBITAL-ZEBRA-SENTINEL" in text
            else [0.0, 1.0]
            for text in texts
        ]


class GovernedHybridRetrievalTests(unittest.TestCase):
    def git(self, root: Path, *args: str) -> str:
        completed = subprocess.run(
            ["git", *args],
            cwd=root,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        return completed.stdout.strip()

    def make_repository(self, root: Path) -> None:
        self.git(root, "init", "-b", "main")
        self.git(root, "config", "user.name", "Retrieval Fixture")
        self.git(root, "config", "user.email", "retrieval-fixture@example.invalid")
        (root / "core").mkdir(parents=True)
        (root / "platform").mkdir()
        (root / "learnings").mkdir()
        (root / "core" / "governance.md").write_text(
            "---\nid: governance\nscope: global\nstatus: active\nprivacy_class: public\n---\n\n"
            "# 记忆治理\n\n高影响内容必须经过显式授权。\n",
            encoding="utf-8",
        )
        (root / "core" / "isolation.md").write_text(
            "---\nid: isolation\nscope: global\nstatus: active\nprivacy_class: public\n---\n\n"
            "# 隔离规则\n\n候选内容不得直接成为长期规则。\n",
            encoding="utf-8",
        )
        (root / "learnings" / "recovery.md").write_text(
            "---\nid: recovery\nscope: learning\nstatus: active\nprivacy_class: public\n---\n\n"
            "# 后台恢复\n\n流水线停滞时，从最近的检查点恢复处理。\n",
            encoding="utf-8",
        )
        self.git(root, "add", ".")
        self.git(root, "commit", "-m", "retrieval fixture")

    def retrieval(self, root: Path) -> GovernedHybridRetrieval:
        authority = MemoryProjection(
            repository=root,
            index_path=root / ".runtime" / "authority.sqlite",
            authority_roots=("core", "platform", "learnings"),
            force_no_fts=True,
        )
        return GovernedHybridRetrieval(
            authority=authority,
            index_path=root / ".runtime" / "hybrid.sqlite",
            embedding=None,
        )

    def test_contiguous_short_chinese_term_recalls_governed_chunk(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_repository(root)
            retrieval = self.retrieval(root)
            built = retrieval.build(context=recall_policy(["global"]))

            result = retrieval.recall(
                "授权",
                context=recall_policy(["global"]),
            )

            self.assertEqual(built["status"], "built")
            self.assertEqual(result["status"], "hit")
            self.assertEqual(result["matches"][0]["item_id"], "governance")
            self.assertEqual(result["matches"][0]["heading"], "记忆治理")
            self.assertTrue(result["matches"][0]["canonical_reopened"])
            self.assertIn("source=core/governance.md@", result["matches"][0]["evidence"])
            self.assertIn("高影响内容必须经过显式授权", result["matches"][0]["evidence"])

    def test_evidence_excerpt_keeps_a_query_match_near_the_end_of_a_large_chunk(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_repository(root)
            marker = "QUARTZ-ANCHOR-77"
            (root / "core" / "window.md").write_text(
                "---\nid: window\nscope: global\nstatus: active\nprivacy_class: public\n---\n\n"
                "# Query Window\n\n"
                + ("ordinary filler " * 180)
                + "\nThe governed key is "
                + marker
                + ".\n",
                encoding="utf-8",
            )
            self.git(root, "add", "core/window.md")
            self.git(root, "commit", "-m", "add query window fixture")
            retrieval = self.retrieval(root)
            retrieval.build(context=recall_policy(["global"]))

            result = retrieval.recall(
                marker,
                context=recall_policy(["global"]),
            )

            self.assertEqual("hit", result["status"])
            self.assertEqual("window", result["matches"][0]["item_id"])
            self.assertIn(marker, result["matches"][0]["evidence"])
            self.assertLessEqual(len(result["matches"][0]["evidence"]), 2800)

    def test_twenty_case_lexical_exact_alias_and_excerpt_development_matrix(self) -> None:
        phrases = [
            "星河校验", "琥珀回执", "青岚游标", "墨竹隔离", "云杉授权",
            "赤霞墓碑", "银杏重建", "玄武索引", "白鹭证据", "金桂下钻",
            "苍穹恢复", "碧海去重", "丹枫审计", "雪松边界", "紫藤版本",
            "晨曦投影", "暮云治理", "松涛检查", "月华来源", "霜叶召回",
        ]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_repository(root)
            for index, phrase in enumerate(phrases):
                (root / "core" / "route-{:02d}.md".format(index)).write_text(
                    "---\nid: route-{index:02d}\nscope: global\nstatus: active\nprivacy_class: public\n---\n\n"
                    "# Route {index:02d}\n\n{filler}\n受治理的检索锚点是 {phrase}。\n".format(
                        index=index,
                        filler="ordinary filler " * 180,
                        phrase=phrase,
                    ),
                    encoding="utf-8",
                )
            self.git(root, "add", "core")
            self.git(root, "commit", "-m", "add retrieval development matrix")
            retrieval = self.retrieval(root)
            retrieval.build(context=recall_policy(["global"]))

            lexical_hits = 0
            exact_hits = 0
            alias_hits = 0
            excerpt_hits = 0
            for index, phrase in enumerate(phrases):
                item_id = "route-{:02d}".format(index)
                lexical = retrieval.recall(
                    phrase,
                    context=recall_policy(["global"]),
                )
                exact = retrieval.recall(
                    "core/route-{:02d}.md".format(index),
                    context=recall_policy(["global"]),
                )
                alias_query = "governed-route-{:02d}".format(index)
                alias = retrieval.recall(
                    alias_query,
                    context=recall_policy(["global"]),
                    aliases={alias_query: [phrase]},
                )
                lexical_hits += int(
                    any(row["item_id"] == item_id for row in lexical["matches"][:5])
                )
                exact_hits += int(
                    bool(exact["matches"] and exact["matches"][0]["item_id"] == item_id)
                )
                alias_hits += int(
                    bool(alias["matches"] and alias["matches"][0]["item_id"] == item_id)
                )
                excerpt_hits += int(
                    bool(lexical["matches"] and phrase in lexical["matches"][0]["evidence"])
                )

            self.assertEqual(len(phrases), lexical_hits)
            self.assertEqual(len(phrases), exact_hits)
            self.assertEqual(len(phrases), alias_hits)
            self.assertEqual(len(phrases), excerpt_hits)

    def test_lexical_ranking_resists_repeated_low_information_alias_spam(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_repository(root)
            (root / "core" / "recovery.md").write_text(
                "---\nid: lexical-spam-recovery\nscope: global\nstatus: active\nprivacy_class: public\n---\n\n"
                "# 恢复协议\n\n"
                "任务恢复依赖持久检查点；进程重启后从已确认游标继续。\n",
                encoding="utf-8",
            )
            for index in range(6):
                (root / "core" / "noise-{}.md".format(index)).write_text(
                    "---\nid: noise-{index}\nscope: global\nstatus: active\nprivacy_class: public\n---\n\n"
                    "# 普通记录\n\n{noise}\n".format(
                        index=index,
                        noise="继续" * 80,
                    ),
                    encoding="utf-8",
                )
            self.git(root, "add", "core")
            self.git(root, "commit", "-m", "add lexical alias-spam matrix")
            retrieval = self.retrieval(root)
            retrieval.build(context=recall_policy(["global"]))

            result = retrieval.recall(
                "任务中断后怎样续跑？",
                context=recall_policy(["global"]),
                limit=5,
            )

            self.assertEqual("hit", result["status"])
            self.assertIn(
                "lexical-spam-recovery",
                [row["item_id"] for row in result["matches"][:5]],
            )

    def test_fielded_query_ranking_generalizes_across_five_lexical_categories(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_repository(root)
            documents = {
                "recovery-playbook": (
                    "core/recovery-playbook.md",
                    "恢复手册",
                    "任务断点续传依赖持久检查点；重启后按确认游标恢复。",
                ),
                "receipt-integrity": (
                    "core/receipt-integrity.md",
                    "授权回执完整性",
                    "授权回执必须绑定来源摘要、执行结果与不可变审计标识。",
                ),
                "mixed-language": (
                    "learnings/mixed-checkpoint.md",
                    "Checkpoint Recovery",
                    "跨语言任务恢复使用检查点恢复协议，并保留 checkpoint evidence。",
                ),
            }
            for item_id, (relative, heading, body) in documents.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(
                    "---\nid: {}\nscope: {}\nstatus: active\nprivacy_class: public\n---\n\n# {}\n\n{}\n".format(
                        item_id,
                        "learning" if relative.startswith("learnings/") else "global",
                        heading,
                        body,
                    ),
                    encoding="utf-8",
                )
            for index in range(8):
                (root / "core" / "distractor-{}.md".format(index)).write_text(
                    "---\nid: field-noise-{0}\nscope: global\nstatus: active\nprivacy_class: public\n---\n\n"
                    "# 普通记录\n\n{1}\n".format(
                        index,
                        ("断点" * 40 if index < 4 else "授权 回执" * 30),
                    ),
                    encoding="utf-8",
                )
            self.git(root, "add", ".")
            self.git(root, "commit", "-m", "add fielded lexical matrix")
            retrieval = self.retrieval(root)
            policy = recall_policy(["global", "learning"])
            retrieval.build(context=policy)

            cases = (
                ("断点续传", "recovery-playbook"),
                ("授权回执完整性", "receipt-integrity"),
                ("请查 core/recovery-playbook.md 的规则", "recovery-playbook"),
                ("recovery-playbook.md 讲什么", "recovery-playbook"),
                ("how to 恢复 from checkpoint", "mixed-language"),
            )
            for query, expected in cases:
                result = retrieval.recall(query, context=policy, limit=5)
                self.assertTrue(result["matches"], (query, result))
                self.assertEqual(
                    expected,
                    result["matches"][0]["item_id"],
                    (query, [row["item_id"] for row in result["matches"]]),
                )

    def test_semantic_calibration_recalls_a_canonical_cross_language_paraphrase(self) -> None:
        class CalibratedSemanticEmbedding:
            def describe(self):
                return {
                    "status": "ready",
                    "provider": "calibration-test",
                    "model": "cross-language-margin-v1",
                    "dimension": 2,
                    "fingerprint": "cross-language-margin-v1",
                    "privacy": "local_only",
                    "network": False,
                }

            def embed(self, texts):
                vectors = []
                for text in texts:
                    if "rotate credentials" in text.casefold():
                        vectors.append([1.0, 0.0])
                    elif "双人复核" in text:
                        vectors.append([0.68, 0.733212111])
                    else:
                        vectors.append([0.30, 0.953939201])
                return vectors

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_repository(root)
            (root / "core" / "credential-rotation.md").write_text(
                "---\nid: credential-rotation\nscope: global\nstatus: active\nprivacy_class: public\n---\n\n"
                "# 凭据轮换\n\n生产凭据轮换必须经过双人复核并保留审计记录。\n",
                encoding="utf-8",
            )
            self.git(root, "add", ".")
            self.git(root, "commit", "-m", "add semantic calibration rule")
            authority = MemoryProjection(
                repository=root,
                index_path=root / ".runtime" / "authority.sqlite",
                authority_roots=("core", "platform", "learnings"),
                force_no_fts=True,
            )
            retrieval = GovernedHybridRetrieval(
                authority=authority,
                index_path=root / ".runtime" / "hybrid.sqlite",
                embedding=CalibratedSemanticEmbedding(),
            )
            policy = recall_policy(["global"])
            retrieval.build(context=policy)

            result = retrieval.recall(
                "require two-person review before we rotate credentials",
                context=policy,
                limit=5,
            )

            self.assertEqual("hit", result["status"])
            self.assertEqual("credential-rotation", result["matches"][0]["item_id"])
            self.assertIn("semantic", result["matches"][0]["retrieval_channels"])

    def test_fielded_ranking_is_invariant_to_document_materialization_order(self) -> None:
        documents = (
            (
                "core/order-target.md",
                "order-target",
                "恢复游标规则",
                "任务恢复必须读取持久检查点，并从确认游标继续执行。",
            ),
            (
                "core/order-noise-a.md",
                "order-noise-a",
                "普通恢复记录",
                "恢复 " * 80,
            ),
            (
                "learnings/order-noise-b.md",
                "order-noise-b",
                "Checkpoint Notes",
                "checkpoint " * 80,
            ),
        )

        def ranked_ids(order: tuple[int, ...]) -> list[str]:
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                self.make_repository(root)
                for index in order:
                    relative, item_id, heading, body = documents[index]
                    path = root / relative
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text(
                        "---\nid: {}\nscope: {}\nstatus: active\nprivacy_class: public\n---\n\n"
                        "# {}\n\n{}\n".format(
                            item_id,
                            "learning" if relative.startswith("learnings/") else "global",
                            heading,
                            body,
                        ),
                        encoding="utf-8",
                    )
                self.git(root, "add", ".")
                self.git(root, "commit", "-m", "add order metamorphic fixture")
                retrieval = self.retrieval(root)
                policy = recall_policy(["global", "learning"])
                retrieval.build(context=policy)
                result = retrieval.recall(
                    "请查 core/order-target.md 的恢复游标规则",
                    context=policy,
                    limit=5,
                )
                return [row["item_id"] for row in result["matches"]]

        forward = ranked_ids((0, 1, 2))
        reversed_order = ranked_ids((2, 1, 0))

        self.assertTrue(forward)
        self.assertEqual("order-target", forward[0])
        self.assertEqual(forward, reversed_order)

    def test_hybrid_recall_rejects_an_unversioned_policy_before_ranking(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_repository(root)
            retrieval = self.retrieval(root)
            retrieval.build(context=recall_policy(["global"]))

            result = retrieval.recall("授权", context={})

            self.assertEqual(result["status"], "abstain")
            self.assertEqual(result["reason"], "recall_policy_invalid")
            self.assertEqual(result["matches"], [])

    def test_hybrid_build_uses_recall_policy_as_of_before_index_or_embedding(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_repository(root)
            (root / "core" / "future.md").write_text(
                "---\nid: future-item\nscope: global\nstatus: active\nprivacy_class: public\n"
                "valid_from: 2026-01-01T00:00:00Z\n---\n\n"
                "# Future\n\nfuture-policy-marker\n",
                encoding="utf-8",
            )
            self.git(root, "add", "core/future.md")
            self.git(root, "commit", "-m", "add future item")
            authority = MemoryProjection(
                repository=root,
                index_path=root / ".runtime" / "authority.sqlite",
                authority_roots=("core", "platform", "learnings"),
                force_no_fts=True,
            )
            retrieval = GovernedHybridRetrieval(
                authority=authority,
                index_path=root / ".runtime" / "hybrid.sqlite",
                embedding=DeterministicSemanticEmbedding(),
            )
            policy = RecallPolicy.from_mapping(
                {
                    **recall_policy(["global"]).to_mapping(),
                    "as_of": "2025-01-01T00:00:00Z",
                }
            )

            authority_built = authority.build(context=policy)
            hybrid_built = retrieval.build(context=policy)

            self.assertLess(
                authority_built["item_count"],
                len(hybrid_built["indexed_item_ids"]),
            )
            self.assertIn("future-item", hybrid_built["indexed_item_ids"])
            self.assertNotIn("future-item", hybrid_built["filtered_item_ids"])

    def test_hybrid_index_admission_is_stable_across_dynamic_recall_policies(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_repository(root)
            (root / "learnings" / "approved-private.md").write_text(
                "---\n"
                "id: approved-private\n"
                "scope: learning\n"
                "status: active\n"
                "authorization_state: user_approved\n"
                "provenance_trust: source_bound_candidate\n"
                "privacy_class: private_local\n"
                "---\n\n"
                "# Approved private work memory\n\n"
                "private-work-recovery-anchor uses the verified checkpoint.\n",
                encoding="utf-8",
            )
            self.git(root, "add", "learnings/approved-private.md")
            self.git(root, "commit", "-m", "add approved private work memory")
            retrieval = self.retrieval(root)

            built = retrieval.build(context=recall_policy(["global"]))
            result = retrieval.recall(
                "private-work-recovery-anchor",
                context=local_work_policy(["learning"]),
            )

            self.assertIn("approved-private", built["indexed_item_ids"])
            self.assertEqual("hit", result["status"])
            self.assertEqual("approved-private", result["matches"][0]["item_id"])

    def test_exact_path_and_cross_language_alias_lanes_are_governed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_repository(root)
            retrieval = self.retrieval(root)
            retrieval.build(context=recall_policy(["global"]))

            exact = retrieval.recall(
                "core/governance.md",
                context=recall_policy(["global"]),
            )
            alias = retrieval.recall(
                "explicit authorization",
                context=recall_policy(["global"]),
                aliases={"explicit authorization": ["显式授权"]},
            )

            self.assertEqual(exact["status"], "hit")
            self.assertEqual(exact["matches"][0]["authority_path"], "core/governance.md")
            self.assertIn("exact_path", exact["matches"][0]["retrieval_channels"])
            self.assertEqual(alias["status"], "hit")
            self.assertEqual(alias["matches"][0]["item_id"], "governance")
            self.assertIn("alias", alias["matches"][0]["retrieval_channels"])

    def test_production_default_aliases_resolve_outdated_rule_to_canonical_revision(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_repository(root)
            (root / "core" / "authority.md").write_text(
                "---\nid: authority\nscope: global\nstatus: active\nprivacy_class: public\n---\n\n"
                "# 权威版本\n\n重新打开 canonical authority 并校验 revision。\n",
                encoding="utf-8",
            )
            self.git(root, "add", "core/authority.md")
            self.git(root, "commit", "-m", "add canonical authority rule")
            retrieval = self.retrieval(root)
            retrieval.build(context=recall_policy(["global"]))

            result = retrieval.recall(
                "回答前怎样确认没有使用旧规则",
                context=recall_policy(["global"]),
            )

            self.assertEqual("hit", result["status"])
            self.assertEqual(["authority"], [row["item_id"] for row in result["matches"]])
            self.assertIn("alias", result["matches"][0]["retrieval_channels"])

    def test_alias_hit_boosts_without_deleting_a_semantic_only_candidate(self) -> None:
        class AliasAndSemanticEmbedding:
            def describe(self):
                return {
                    "status": "ready",
                    "provider": "deterministic-test",
                    "model": "alias-plus-semantic-v1",
                    "dimension": 2,
                    "fingerprint": "alias-plus-semantic-v1",
                    "privacy": "local_only",
                    "network": False,
                }

            def embed(self, texts):
                vectors = []
                for text in texts:
                    if "旧规则" in text or "深层语义候选" in text:
                        vectors.append([1.0, 0.0])
                    else:
                        vectors.append([0.0, 1.0])
                return vectors

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_repository(root)
            (root / "core" / "authority.md").write_text(
                "---\nid: authority\nscope: global\nstatus: active\nprivacy_class: public\n---\n\n"
                "# Authority\n\n重新打开 canonical authority 并校验 revision。\n",
                encoding="utf-8",
            )
            (root / "core" / "semantic-only.md").write_text(
                "---\nid: semantic-only\nscope: global\nstatus: active\nprivacy_class: public\n---\n\n"
                "# Semantic Only\n\n深层语义候选描述了另一条可复用的核验方法。\n",
                encoding="utf-8",
            )
            self.git(root, "add", "core")
            self.git(root, "commit", "-m", "add alias and semantic candidates")
            authority = MemoryProjection(
                repository=root,
                index_path=root / ".runtime" / "authority.sqlite",
                authority_roots=("core", "platform", "learnings"),
                force_no_fts=True,
            )
            retrieval = GovernedHybridRetrieval(
                authority=authority,
                index_path=root / ".runtime" / "hybrid.sqlite",
                embedding=AliasAndSemanticEmbedding(),
            )
            policy = recall_policy(["global"])
            retrieval.build(context=policy)

            result = retrieval.recall(
                "怎样确认没有使用旧规则",
                context=policy,
                limit=5,
            )

            matches = {row["item_id"]: row for row in result["matches"]}
            self.assertIn("authority", matches)
            self.assertIn("alias", matches["authority"]["retrieval_channels"])
            self.assertIn("semantic-only", matches)
            self.assertEqual(
                ["semantic"], matches["semantic-only"]["retrieval_channels"]
            )

    def test_explicit_retired_memory_request_fails_closed_before_current_recall(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_repository(root)
            (root / "core" / "fjord.md").write_text(
                "---\nid: fjord\nscope: global\nstatus: active\nprivacy_class: public\n---\n\n"
                "# Fjord\n\nCurrent command: fjord validate --offline.\n",
                encoding="utf-8",
            )
            self.git(root, "add", "core/fjord.md")
            self.git(root, "commit", "-m", "add current fjord command")
            retrieval = self.retrieval(root)
            retrieval.build(context=recall_policy(["global"]))

            result = retrieval.recall(
                "Return the remembered retired Fjord token only",
                context=recall_policy(["global"]),
            )

            self.assertEqual("abstain", result["status"])
            self.assertEqual("retired_memory_query", result["reason"])
            self.assertEqual([], result["matches"])

    def test_tombstone_filters_even_high_scoring_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_repository(root)
            item = root / "core" / "governance.md"
            item_hash = __import__("hashlib").sha256(item.read_bytes()).hexdigest()
            (root / "lifecycle" / "tombstones").mkdir(parents=True)
            (root / "lifecycle" / "tombstones" / "governance.json").write_text(
                __import__("json").dumps(
                    {
                        "schema_version": 1,
                        "tombstone_id": "tomb-governance",
                        "item_id": "governance",
                        "authority_path": "core/governance.md",
                        "authority_sha256": item_hash,
                        "reason": "fixture deletion",
                        "approval_receipt": "receipt-governance",
                        "created_at": "2026-08-14T00:00:00Z",
                        "runtime_purge_binding": {
                            "schema_version": 1,
                            "scope": "whole_sessions",
                            "target_candidate_ids": ["cand_" + "a" * 64],
                            "session_selector_digests": ["b" * 64],
                        },
                    }
                ),
                encoding="utf-8",
            )
            self.git(root, "add", ".")
            self.git(root, "commit", "-m", "tombstone fixture")
            retrieval = self.retrieval(root)
            retrieval.build(context=recall_policy(["global"]))

            tombstoned = retrieval.recall(
                "授权",
                context=recall_policy(["global"]),
            )
            self.assertTrue(all(match["item_id"] != "governance" for match in tombstoned["matches"]))

    def test_index_contains_candidate_identifiers_not_authority_content_or_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_repository(root)
            retrieval = self.retrieval(root)
            retrieval.build(context=recall_policy(["global"]))

            connection = sqlite3.connect(str(retrieval.index_path))
            try:
                columns = [row[1] for row in connection.execute("PRAGMA table_info(candidates)")]
            finally:
                connection.close()
            raw = retrieval.index_path.read_bytes()

            self.assertEqual(columns, ["chunk_id", "item_id", "ordinal"])
            self.assertNotIn("core/governance.md".encode(), raw)
            self.assertNotIn("高影响内容必须经过显式授权".encode(), raw)

    def test_semantic_candidate_is_rrf_fused_then_revalidated_from_canonical_chunk(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_repository(root)
            authority = MemoryProjection(
                repository=root,
                index_path=root / ".runtime" / "authority.sqlite",
                authority_roots=("core", "platform", "learnings"),
                force_no_fts=True,
            )
            retrieval = GovernedHybridRetrieval(
                authority=authority,
                index_path=root / ".runtime" / "hybrid.sqlite",
                embedding=DeterministicSemanticEmbedding(),
            )
            built = retrieval.build(context=recall_policy(["learning"]))

            result = retrieval.recall(
                "resume stalled background work",
                context=recall_policy(["learning"]),
            )

            self.assertEqual(built["semantic"]["status"], "ready")
            self.assertEqual(result["status"], "hit")
            self.assertEqual(result["retrieval_mode"], "hybrid")
            self.assertEqual(result["matches"][0]["item_id"], "recovery")
            self.assertIn("semantic", result["matches"][0]["retrieval_channels"])
            self.assertGreaterEqual(result["matches"][0]["semantic_similarity"], 0.75)
            self.assertTrue(result["matches"][0]["canonical_reopened"])

    def test_oversized_section_is_segmented_before_embedding(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_repository(root)
            huge_body = "超长正文" * 18000
            (root / "core" / "oversized.md").write_text(
                "---\nid: oversized\nscope: global\nstatus: active\nprivacy_class: public\n---\n\n"
                "# Oversized\n\n" + huge_body + "\n",
                encoding="utf-8",
            )
            self.git(root, "add", "core/oversized.md")
            self.git(root, "commit", "-m", "add oversized authority section")
            authority = MemoryProjection(
                repository=root,
                index_path=root / ".runtime" / "authority.sqlite",
                authority_roots=("core", "platform", "learnings"),
                force_no_fts=True,
            )
            embedding = SizeBoundSemanticEmbedding()
            retrieval = GovernedHybridRetrieval(
                authority=authority,
                index_path=root / ".runtime" / "hybrid.sqlite",
                embedding=embedding,
            )

            built = retrieval.build(context=recall_policy(["global"]))
            connection = sqlite3.connect(str(retrieval.index_path))
            try:
                candidate_count = connection.execute(
                    "SELECT COUNT(*) FROM candidates"
                ).fetchone()[0]
                semantic_count = connection.execute(
                    "SELECT COUNT(*) FROM semantic"
                ).fetchone()[0]
            finally:
                connection.close()

            self.assertEqual("ready", built["semantic"]["status"])
            self.assertGreater(built["chunk_count"], 4)
            self.assertEqual(candidate_count, semantic_count)
            self.assertLessEqual(max(embedding.seen_sizes), 4 * 1024)
            self.assertLessEqual(max(embedding.seen_batch_sizes), 2 * 1024 * 1024)

    def test_semantic_recall_reopens_a_later_segment_of_a_large_section(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_repository(root)
            filler = "\n\n".join(["ordinary filler " * 280 for _ in range(8)])
            (root / "core" / "later-segment.md").write_text(
                "---\nid: later-segment\nscope: global\nstatus: active\nprivacy_class: public\n---\n\n"
                "# Large Semantic Section\n\n"
                + filler
                + "\n\nORBITAL-ZEBRA-SENTINEL is the governed later-segment evidence.\n",
                encoding="utf-8",
            )
            self.git(root, "add", "core/later-segment.md")
            self.git(root, "commit", "-m", "add later semantic evidence")
            authority = MemoryProjection(
                repository=root,
                index_path=root / ".runtime" / "authority.sqlite",
                authority_roots=("core", "platform", "learnings"),
                force_no_fts=True,
            )
            retrieval = GovernedHybridRetrieval(
                authority=authority,
                index_path=root / ".runtime" / "hybrid.sqlite",
                embedding=SizeBoundSemanticEmbedding(),
            )
            retrieval.build(context=recall_policy(["global"]))

            result = retrieval.recall(
                "remote semantic concept",
                context=recall_policy(["global"]),
            )

            self.assertEqual("hit", result["status"])
            self.assertEqual("later-segment", result["matches"][0]["item_id"])
            self.assertGreater(result["matches"][0]["segment_index"], 0)
            self.assertIn("semantic", result["matches"][0]["retrieval_channels"])
            self.assertIn("ORBITAL-ZEBRA-SENTINEL", result["matches"][0]["evidence"])

    def test_unchanged_segment_ids_survive_a_sibling_segment_update(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_repository(root)

            def paragraph(marker: str, filler: str) -> str:
                return marker + " " + ((filler + " ") * 280)

            segmented = root / "core" / "segmented.md"
            segmented.write_text(
                "---\nid: segmented\nscope: global\nstatus: active\nprivacy_class: public\n---\n\n"
                "# Stable Segments\n\n"
                + paragraph("alpha-unchanged", "alpha-filler")
                + "\n\n"
                + paragraph("middle-old", "middle-filler")
                + "\n\n"
                + paragraph("omega-unchanged", "omega-filler")
                + "\n",
                encoding="utf-8",
            )
            self.git(root, "add", "core/segmented.md")
            self.git(root, "commit", "-m", "add stable segments")
            retrieval = self.retrieval(root)
            context = recall_policy(["global"])
            retrieval.build(context=context)
            before = {
                marker: retrieval.recall(marker, context=context)["matches"][0]
                for marker in ("alpha-unchanged", "middle-old", "omega-unchanged")
            }

            segmented.write_text(
                "---\nid: segmented\nscope: global\nstatus: active\nprivacy_class: public\n---\n\n"
                "# Stable Segments\n\n"
                + paragraph("alpha-unchanged", "alpha-filler")
                + "\n\n"
                + paragraph("middle-new", "middle-filler")
                + "\n\n"
                + paragraph("omega-unchanged", "omega-filler")
                + "\n",
                encoding="utf-8",
            )
            self.git(root, "add", "core/segmented.md")
            self.git(root, "commit", "-m", "update middle segment")
            retrieval.build(context=context)
            after = {
                marker: retrieval.recall(marker, context=context)["matches"][0]
                for marker in ("alpha-unchanged", "middle-new", "omega-unchanged")
            }

            self.assertEqual(
                before["alpha-unchanged"]["heading_id"],
                after["alpha-unchanged"]["heading_id"],
            )
            self.assertEqual(
                before["alpha-unchanged"]["chunk_id"],
                after["alpha-unchanged"]["chunk_id"],
            )
            self.assertNotEqual(
                before["middle-old"]["chunk_id"], after["middle-new"]["chunk_id"]
            )
            self.assertEqual(
                before["omega-unchanged"]["chunk_id"],
                after["omega-unchanged"]["chunk_id"],
            )

    @unittest.skipUnless(sys.platform == "darwin", "NaturalLanguage is a macOS framework")
    def test_macos_natural_language_embedding_is_local_versioned_and_finite(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provider = LocalNaturalLanguageEmbedding(
                helper_source=ROOT / "scripts" / "agent_memory_embedding.swift",
                cache_dir=Path(temporary),
            )

            try:
                description = provider.describe()
            except EmbeddingUnavailable as error:
                if "simplified Chinese sentence embedding is unavailable" in str(error):
                    self.skipTest("macOS runner does not provide the Simplified Chinese embedding asset")
                raise
            vectors = provider.embed(["显式授权", "检查点恢复"])

            self.assertEqual(description["status"], "ready")
            self.assertEqual(description["provider"], "macos_natural_language")
            self.assertEqual(description["privacy"], "local_only")
            self.assertTrue(description["runtime_version"])
            self.assertRegex(description["fingerprint"], r"^[0-9a-f]{64}$")
            self.assertEqual(len(vectors), 2)
            self.assertEqual(len(vectors[0]), description["dimension"])
            self.assertTrue(all(value == value and abs(value) <= 1.0 for value in vectors[0]))

    def test_embedding_fingerprint_drift_fails_semantic_lane_closed(self) -> None:
        class FingerprintedEmbedding:
            def __init__(self, fingerprint: str, **overrides) -> None:
                self.manifest = {
                    "status": "ready", "provider": "fixture", "model": "fixture-model",
                    "dimension": 2, "fingerprint": fingerprint,
                    "privacy": "local_only", "network": False,
                }
                self.manifest.update(overrides)

            def describe(self):
                return dict(self.manifest)

            def embed(self, texts):
                return [[1.0, 0.0] for _ in texts]

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_repository(root)
            authority = MemoryProjection(
                repository=root,
                index_path=root / ".runtime" / "authority.sqlite",
                authority_roots=("core", "platform", "learnings"),
                force_no_fts=True,
            )
            index = root / ".runtime" / "fingerprint.sqlite"
            GovernedHybridRetrieval(
                authority=authority, index_path=index,
                embedding=FingerprintedEmbedding("fingerprint-a"),
            ).build(context=recall_policy(["learning"]))

            changes = {
                "provider": "other-provider",
                "model": "other-model",
                "dimension": 3,
                "fingerprint": "fingerprint-b",
                "privacy": "external",
                "network": True,
            }
            for key, value in changes.items():
                with self.subTest(key=key):
                    overrides = {key: value}
                    fingerprint = str(overrides.pop("fingerprint", "fingerprint-a"))
                    result = GovernedHybridRetrieval(
                        authority=authority, index_path=index,
                        embedding=FingerprintedEmbedding(fingerprint, **overrides),
                    ).recall(
                        "resume stalled background work",
                        context=recall_policy(["learning"]),
                    )

                    self.assertEqual("degraded", result["semantic"]["status"])
                    self.assertIn("mismatch", result["semantic"]["reason"])
                    self.assertNotIn(
                        "semantic",
                        [lane for match in result["matches"] for lane in match["retrieval_channels"]],
                    )

    def test_ready_semantic_index_without_runtime_embedding_degrades_to_lexical(self) -> None:
        class ReadyEmbedding:
            def describe(self):
                return {
                    "status": "ready", "provider": "fixture", "model": "fixture-model",
                    "dimension": 2, "fingerprint": "fixture-fingerprint",
                    "privacy": "local_only", "network": False,
                }

            def embed(self, texts):
                return [[1.0, 0.0] for _ in texts]

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_repository(root)
            authority = MemoryProjection(
                repository=root,
                index_path=root / ".runtime" / "authority.sqlite",
                authority_roots=("core", "platform", "learnings"),
                force_no_fts=True,
            )
            index = root / ".runtime" / "embedding-missing.sqlite"
            GovernedHybridRetrieval(
                authority=authority, index_path=index, embedding=ReadyEmbedding()
            ).build(context=recall_policy(["learning"]))

            result = GovernedHybridRetrieval(
                authority=authority, index_path=index, embedding=None
            ).recall(
                "后台任务",
                context=recall_policy(["learning"]),
            )

            self.assertEqual("degraded", result["semantic"]["status"])
            self.assertEqual("embedding_unavailable_at_recall", result["semantic"]["reason"])
            self.assertEqual("lexical", result["retrieval_mode"])


if __name__ == "__main__":
    unittest.main()
