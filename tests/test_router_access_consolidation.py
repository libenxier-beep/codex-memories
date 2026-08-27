from __future__ import annotations

import ast
import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BASELINE_COMMIT = "03469eca092f241448f9a803e41c8c785ccebf50"
CAPTURE_BASELINE = os.environ.get("CAPTURE_ROUTER_ACCESS_BASELINE") == "1"
EXPECTED_BASELINE_DIGESTS = {
    "6e03c0d9158f646ceb1a": "3e06d1a421b356c6f9d054e425dd7a7bfc8b3d2f5e8ab085dde8b1532822c21f",
    "588778703b892923833a": "803611a41f3416add51d70bc37861ee73c7074a819387b52da4eff71846f7e63",
    "a819d570d21d4b500eab": "d1a979fec3141ae0fb4031c1eb62ad0b93e088be67abbbcc9c4c51f09e562c54",
    "ccace55f5f01bdb2c8a4": "3e06d1a421b356c6f9d054e425dd7a7bfc8b3d2f5e8ab085dde8b1532822c21f",
    "c83f5a1f4fa571ff24bf": "803611a41f3416add51d70bc37861ee73c7074a819387b52da4eff71846f7e63",
    "e4358b3f96d5ecb7f318": "d1a979fec3141ae0fb4031c1eb62ad0b93e088be67abbbcc9c4c51f09e562c54",
    "d6e88073ea60c685b6d2": "96c6d60ffc2e914c5ab1b71a12ca75cbab4c00f90ed6b468d4bacd6fae62812c",
    "5fcb98eacf8b871dafb8": "237a5a4724055c0d32689ea1f96bda0dc4158106f51a6663e65416d74061cf81",
    "4ed42cf71f14dc2ac105": "eb61ce4f6d3f2f500fac63c25d053eb471f71d67084838d26fbcf0b9d2073176",
    "841710df40bd1b5b1fe8": "fdb090f0c3d95102b7c0152eb48826ecff7c56d0b836c57d75433d4435117d86",
    "7e60147841fa15ab118a": "5c4d8700ccb8f5a23827f28993023bff093d6d0a9f5001c627a64cd6c8e01978",
    "600b364dca0d5f5db61b": "e374dbfaf38848d108f9404d7b0ba8db95e264a07800cd6336d088d54d8b4844",
    "79b375abea169c0e7c50": "e374dbfaf38848d108f9404d7b0ba8db95e264a07800cd6336d088d54d8b4844",
    "5cde7a35c8f53b50a3fb": "e374dbfaf38848d108f9404d7b0ba8db95e264a07800cd6336d088d54d8b4844",
    "7dc2b76ffe81dcc48dee": "e374dbfaf38848d108f9404d7b0ba8db95e264a07800cd6336d088d54d8b4844",
    "bdd0312842e28023fc4a": "64095dcdc8f928179aac09e90574af0365b6b76b9eb1b6efcb6ff5f4363cb4cf",
    "869cb1e67e6b32662313": "3952595ddebc541cbf2aefccf4b058cf6b8e25a40f44b86733c694c535027283",
    "4122388945f1fc16f6cf": "bcf0f77ed0f10fe594c4d7859c3d054efa13c249824150c207555299dea04e99",
    "1a4aaff022b0761de009": "d83875089c4ebb43ad5f3c83767de4d1a071dbca5fe468f5a6ed3c5000793891",
    "8b4ceef554d6788e3813": "3cf7d852939a6cc43d976b36cc083432ab5c4daaf9839d86f4132ad1394b86cf",
    "f113418e4a13671c6642": "465d4c0d95ed459768b45c302562af0ae389687849232fdaeed9e98143fbd2d6",
    "ba4dc7d89104da4cf393": "422461f2062da86a2cbd13ca25e55f0720a4ff39c51b3752b1a8186107fa91bf",
    "b346a4ce508716037bb6": "161cc89c537b36aeccfb5be4256792bd947f434bc077a6ffa21b10dac89b5e60",
    "61c594a2bba7a72cd0fc": "40044c4e97bddeb363d4b159430a81557780425107f5efff0c6422ff633e6411",
    "5c74e6d29e2aea593f31": "6cc431ca49b5960aabb437a3691ef8cad4c55175a144cc171193cab183379e80",
    "98151fe33666ef8e1501": "6cc431ca49b5960aabb437a3691ef8cad4c55175a144cc171193cab183379e80",
    "b309cdac73929fcb49cc": "af7542ee1dfdfd1cb0eddea1c3ffc553e727d7746721d2f346393995aeea97c2",
    "95f3a45882ab1289daab": "2257a0d0abf4cd9b0ee96467a0911fce4931b95bbe39f0a3b934d27af27dca86",
    "592e3f0f80dbad3fc752": "386316175023479a4b7abd3b121a0ba3fba4c86196c5e59130c4f9ab93698877",
    "9eac8419d8794a680ca5": "8268e4a685705f2fd2b6bf7a008f81c212fca0c109db43ff249075ab659affde",
    "0a1aa17f97fecc0c5199": "85c95df075ee66827cff251dc97a6a268b575a4eb2f969a9add85994e646e316",
    "d58bff7dcb9d7c902095": "386316175023479a4b7abd3b121a0ba3fba4c86196c5e59130c4f9ab93698877",
    "d1ddaeb9ea6e46f4b318": "eca3a21acade039ba62daa2cdea5d1f61ff33ddf6d07e613c3dcb05bc77786e3",
    "13590104f6094bdbe8dd": "3e06d1a421b356c6f9d054e425dd7a7bfc8b3d2f5e8ab085dde8b1532822c21f",
    "4d0dbd25f46b8b9375a0": "3e06d1a421b356c6f9d054e425dd7a7bfc8b3d2f5e8ab085dde8b1532822c21f",
    "b6cb5a7e92cd76aca30e": "3e06d1a421b356c6f9d054e425dd7a7bfc8b3d2f5e8ab085dde8b1532822c21f",
    "1152ba1b00c7acd47a90": "3e06d1a421b356c6f9d054e425dd7a7bfc8b3d2f5e8ab085dde8b1532822c21f",
    "d9c8208f19ce3a6950c9": "67f5c69e66a42b6486de1cbbedf2799988634d481c5879480cf30b94be664aec",
    "83472e31329bb223ff82": "115c59ad13c76a40244cfe36eee7b19cd0f3b8ebc4155afa5a993f1ecb0b575a",
    "41a8966ad71ec894943d": "3d93b8e04de653e8a1ad786de4f95fd22257ff1a42b36d8d2203102a5be267fe",
    "d7e91a03e52263a90289": "1f53a64d2c6f09dd130f12dd01d5b63e7d3c193a05154c9954313e6f3fb7022c",
    "6a57ce87fdefc3f81b3e": "f846bd7715f72d9187fc61ea2e9e958fa82368b18d730a136f6fd2586c948e1a",
    "569d68b67fbed17ff8cc": "3c0eaef5fe6d1e205090b8403a5971a5661307e332f0eb00d544c21ea691e5f8",
    "4337dd66951d02a7ff3b": "3c0eaef5fe6d1e205090b8403a5971a5661307e332f0eb00d544c21ea691e5f8",
    "19b8bf154496a638f8de": "3c0eaef5fe6d1e205090b8403a5971a5661307e332f0eb00d544c21ea691e5f8",
    "9c96d4faaecde04ebf72": "3c0eaef5fe6d1e205090b8403a5971a5661307e332f0eb00d544c21ea691e5f8",
    "dac22597fc6bc06943a1": "3c0eaef5fe6d1e205090b8403a5971a5661307e332f0eb00d544c21ea691e5f8",
    "7a881834700be1a39a98": "d17624f5105063ac7a5bc61e7491df10ea9b2e3db94c65122503720013e1b1be",
    "1b8f4fe71c09ce93a046": "8135eda4f14aebd80b2dd438696a918794c7a707d7b14d6c3bf6f855db846031",
    "747b552954f8f4bea5d7": "92118f939c164e09eab1a264d6a9e7b56c6241edc295044a1a5177e0460300be",
    "9f350b617f7a02dd4583": "b4a7e2f6a491a612404dc1aa530b7041637058dbb4e0766735857223ecb93496",
    "091aa9babf896ab80f83": "566e1536708fdff23ffada62b40d27ff7f6536c59d86bb114599a57a5f63672c",
    "20bbc5933ab9cd49103e": "9f3eed6337de2f85d1ce963ba7cb4f287d9fff31fa752fa4608d9b36fe8ebae1",
    "3a7702590bf8f93a92d6": "4115d6e6f66045162d0881a63334d924734465df54b48858fb573094aaba792c",
    "a2a5a6dd53d108816d1d": "e5b2f36812060d97ce6d5e6b85b82c3b46d8556ca53794c3bc5a48af59961c9a",
    "c0847d8a8b0ed7197448": "88ad0b4e743ba550cac976359a42b67b4fa4e0920ce44e2a8f1d2d39462f8147",
    "e84cc3cbf4a13dbf901f": "f852fb476afec4a501949afa80bc50cfa3c79f16155691733cb3e1595e3be86a",
    "6881f6cd1e48dbb9acc2": "f852fb476afec4a501949afa80bc50cfa3c79f16155691733cb3e1595e3be86a",
    "86701db0580d3dc7a1df": "4c2e6bc0477009f9d44333f358c2919af726dbe754b79a545c74899e9cc0e95c",
}


DRIVER = r"""
import importlib
import json
import sys
from pathlib import Path


PATH_KEYS = {
    "root",
    "router_root",
    "codex_home",
    "graph_root",
    "projection_path",
    "hybrid_projection_path",
}


def decode_paths(options):
    decoded = {
        key: Path(value) if key in PATH_KEYS and value is not None else value
        for key, value in options.items()
    }
    for key in ("allowed_scopes", "recall_scopes"):
        if key in decoded:
            decoded[key] = tuple(decoded[key])
    return decoded


payload = json.loads(sys.stdin.read())
try:
    if payload["call"] == "function":
        module = importlib.import_module(payload["module"])
        function = getattr(module, payload["function"])
        value = function(payload.get("query"), **decode_paths(payload.get("options", {})))
    elif payload["call"] == "public_names":
        module = importlib.import_module(payload["module"])
        value = sorted(name for name in dir(module) if not name.startswith("_"))
    elif payload["call"] == "resolve_sources":
        module = importlib.import_module(payload["module"])
        root = Path(payload["root"])
        registry = module.load_collection_registry(root)
        if payload.get("poison_path"):
            import os

            os.environ["PATH"] = "/definitely-missing"
        if payload["plural"]:
            sources = module.resolve_collection_sources(root, registry)
        else:
            collection = next(
                item for item in registry["collections"]
                if item["id"] == payload["collection_id"]
            )
            source = module.resolve_collection_source(root, collection)
            sources = {payload["collection_id"]: source}
        value = {
            identifier: source.public_trace()
            for identifier, source in sorted(sources.items())
        }
    elif payload["call"] == "progressive":
        progressive = importlib.import_module("progressive_knowledge_access")

        class StopAfterBootstrap:
            def plan(self, observation):
                return progressive.PlannerDecision(
                    evidence_status="complete",
                    missing_facets=(),
                    confidence=0.9,
                    actions=(),
                    final_evidence_ids=(),
                    stop_reason="no_answer_calibrated",
                )

        options = decode_paths(payload.get("options", {}))
        value = progressive.progressive_access_knowledge(
            payload["query"],
            enabled=True,
            planner=StopAfterBootstrap(),
            query_id="synthetic-progressive-bootstrap",
            **options,
        )
    else:
        raise ValueError("unsupported differential driver call")
except Exception as error:
    result = {
        "ok": False,
        "error_type": type(error).__name__,
        "message": str(error),
    }
else:
    result = {"ok": True, "value": value}
print(json.dumps(result, ensure_ascii=False, sort_keys=True))
"""


ROUTER_ENGINE = r"""
import hashlib
import json


def _validate_registry(payload):
    if not isinstance(payload, dict) or not isinstance(payload.get("contexts"), list):
        raise ValueError("synthetic registry is invalid")
    return payload


def load_registry(root):
    return _validate_registry(json.loads((root / "contexts.registry.json").read_text(encoding="utf-8")))


def _fingerprint(query):
    return hashlib.sha256(query.encode("utf-8")).hexdigest()[:16]


def _matches(query, context):
    folded = query.casefold()
    values = [context.get("id"), context.get("summary"), *context.get("triggers", [])]
    return sum(
        1
        for value in values
        if isinstance(value, str) and value.casefold() in folded
    )


def route(query, registry, root=None):
    if "no-result" in query.casefold() or "不存在" in query:
        return {
            "decision": "abstain",
            "primary": None,
            "alternatives": [],
            "current_sources_required": False,
            "query_fingerprint": _fingerprint(query),
            "reasons": ["no_match"],
            "trace": {
                "router_version": "2",
                "retrieval_backend": "synthetic",
                "degraded_reason": None,
                "evidence_candidates_read": 0,
            },
        }
    candidates = []
    for context in registry["contexts"]:
        if context.get("status") != "active":
            continue
        score = _matches(query, context)
        if score:
            candidates.append((score, context["id"], context))
    candidates.sort(key=lambda item: (-item[0], item[1]))
    if not candidates:
        return {
            "decision": "abstain",
            "primary": None,
            "alternatives": [],
            "current_sources_required": False,
            "query_fingerprint": _fingerprint(query),
            "reasons": ["no_match"],
            "trace": {
                "router_version": "2",
                "retrieval_backend": "synthetic",
                "degraded_reason": None,
                "evidence_candidates_read": 0,
            },
        }
    score, identifier, selected = candidates[0]
    alternatives = [
        {
            "context_id": other_id,
            "score": float(other_score),
            "path": other["path"],
            "reasons": ["synthetic_trigger"],
        }
        for other_score, other_id, other in candidates[1:3]
    ]
    deeper_matches = []
    if root is not None and ("multi-hop" in query.casefold() or "多跳" in query):
        deeper_matches.append(
            {
                "path": selected.get("deeper_files", [selected["path"]])[0],
                "score": 2.0,
                "reasons": ["ordered_path:1"],
            }
        )
    return {
        "decision": "load",
        "primary": identifier,
        "primary_score": float(score),
        "confidence": "medium",
        "first_file": selected["path"],
        "alternatives": alternatives,
        "deeper_suggestions": list(selected.get("deeper_files", [])),
        "deeper_matches": deeper_matches,
        "current_sources_required": False,
        "query_fingerprint": _fingerprint(query),
        "reasons": ["synthetic_trigger"],
        "trace": {
            "router_version": "2",
            "retrieval_backend": "synthetic",
            "degraded_reason": None,
            "evidence_candidates_read": len(candidates),
        },
    }
"""


class ConsolidationStructureTests(unittest.TestCase):
    """Keep compatibility modules as adapters, never second implementation owners."""

    def top_level_definitions(self, relative: str) -> tuple[set[str], set[str]]:
        tree = ast.parse((ROOT / relative).read_text(encoding="utf-8"))
        functions = {
            node.name
            for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        classes = {node.name for node in tree.body if isinstance(node, ast.ClassDef)}
        return functions, classes

    def test_legacy_router_is_a_thin_compatibility_adapter(self) -> None:
        functions, classes = self.top_level_definitions("scripts/knowledge_router.py")

        self.assertEqual(
            functions,
            {
                "resolve_collection_source",
                "resolve_collection_sources",
                "route_knowledge",
                "evaluate_knowledge_routes",
            },
        )
        self.assertEqual(classes, set())

    def test_legacy_access_is_a_thin_compatibility_adapter(self) -> None:
        functions, classes = self.top_level_definitions("scripts/knowledge_access.py")

        self.assertEqual(functions, {"access_knowledge", "main"})
        self.assertEqual(classes, set())


class RouterAccessDifferentialTests(unittest.TestCase):
    """Compare every retained entrypoint with the frozen public baseline commit."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory()
        cls.sandbox = Path(cls.temporary.name)
        cls.baseline_root = cls.sandbox / "baseline"
        cls.fixture_root = cls.sandbox / "authority"
        cls.graph_root = cls.sandbox / "graphs"
        cls.codex_home = cls.sandbox / "codex-home"
        cls.projection_path = cls.sandbox / "indexes" / "memory.sqlite"
        cls.hybrid_projection_path = cls.sandbox / "indexes" / "hybrid.sqlite"
        cls.baseline_available = cls._extract_baseline()
        cls._make_authority_fixture()
        cls._make_layered_fixture()
        cls._build_projection()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    @classmethod
    def git(cls, root: Path, *args: str) -> str:
        environment = dict(os.environ)
        environment.update(
            {
                "GIT_AUTHOR_DATE": "2026-08-27T00:00:00Z",
                "GIT_COMMITTER_DATE": "2026-08-27T00:00:00Z",
            }
        )
        completed = subprocess.run(
            ["git", *args],
            cwd=root,
            env=environment,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        return completed.stdout.strip()

    @classmethod
    def write_json(cls, path: Path, value: object) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    @classmethod
    def _extract_baseline(cls) -> bool:
        if os.environ.get("FORCE_FROZEN_ROUTER_ACCESS_BASELINE") == "1":
            return False
        available = subprocess.run(
            ["git", "cat-file", "-e", f"{BASELINE_COMMIT}^{{commit}}"],
            cwd=ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        ).returncode == 0
        if not available:
            return False
        archive = subprocess.run(
            ["git", "archive", "--format=tar", BASELINE_COMMIT, "scripts"],
            cwd=ROOT,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).stdout
        cls.baseline_root.mkdir()
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as bundle:
            bundle.extractall(cls.baseline_root)
        return True

    @classmethod
    def _context(cls, identifier: str, title: str, triggers: list[str]) -> dict[str, object]:
        directory = identifier
        return {
            "id": identifier,
            "title": title,
            "summary": f"Synthetic public context for {title}.",
            "path": f"{directory}/README.md",
            "triggers": triggers,
            "non_triggers": [],
            "routing_profile": {"terms": triggers, "boost_groups": []},
            "read_path": [f"{directory}/README.md"],
            "deeper_files": [f"{directory}/details.md"],
            "deeper_routes": [],
            "status": "active",
        }

    @classmethod
    def _write_context_files(cls, root: Path, contexts: list[dict[str, object]]) -> None:
        for context in contexts:
            directory = root / str(context["id"])
            directory.mkdir(parents=True, exist_ok=True)
            title = str(context["title"])
            (directory / "README.md").write_text(
                f"# {title}\n\nSynthetic governed evidence for {title}.\n",
                encoding="utf-8",
            )
            (directory / "details.md").write_text(
                f"# {title} details\n\nOrdered path and multi-hop evidence for {title}.\n",
                encoding="utf-8",
            )

    @classmethod
    def _make_authority_fixture(cls) -> None:
        child_source = cls.sandbox / "work-source"
        child_source.mkdir()
        cls.git(child_source, "init", "-b", "main")
        cls.git(child_source, "config", "user.name", "Synthetic Fixture")
        cls.git(child_source, "config", "user.email", "fixture@example.invalid")
        work_contexts = [
            cls._context(
                "agent_memory_knowledge_bases",
                "Agent Memory Knowledge Bases",
                ["agent memory", "长期记忆", "conversation recall"],
            ),
            cls._context(
                "backend_retrieval_information_flow",
                "Backend Retrieval Information Flow",
                ["backend retrieval", "后端检索", "ordered path", "multi-hop", "多跳"],
            ),
            cls._context(
                "mcp",
                "Model Context Protocol",
                ["mcp", "model context protocol", "工具授权资源"],
            ),
        ]
        (child_source / "README.md").write_text(
            "# Synthetic Work Contexts\n\nPublic test-only authority.\n",
            encoding="utf-8",
        )
        (child_source / "engine.py").write_text(textwrap.dedent(ROUTER_ENGINE), encoding="utf-8")
        cls.write_json(
            child_source / "contexts.registry.json",
            {"schema_version": "2.0", "contexts": work_contexts},
        )
        cls._write_context_files(child_source, work_contexts)
        cls.git(child_source, "add", ".")
        cls.git(child_source, "commit", "-m", "synthetic work authority")
        child_revision = cls.git(child_source, "rev-parse", "HEAD")

        cls.fixture_root.mkdir()
        cls.git(cls.fixture_root, "init", "-b", "main")
        cls.git(cls.fixture_root, "config", "user.name", "Synthetic Fixture")
        cls.git(cls.fixture_root, "config", "user.email", "fixture@example.invalid")
        subprocess.run(
            ["git", "clone", "--quiet", str(child_source), "work_contexts"],
            cwd=cls.fixture_root,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        personal_contexts = [
            cls._context(
                "nutrition_body_composition",
                "Nutrition and Body Composition",
                ["nutrition", "body composition", "营养", "体成分"],
            )
        ]
        personal = cls.fixture_root / "personal_knowledge"
        personal.mkdir()
        (personal / "README.md").write_text(
            "# Synthetic Personal Knowledge\n\nPortable public methods only.\n",
            encoding="utf-8",
        )
        cls.write_json(
            personal / "contexts.registry.json",
            {"schema_version": "2.0", "contexts": personal_contexts},
        )
        cls._write_context_files(personal, personal_contexts)

        registry = {
            "schema_version": 1,
            "generated_at": "2026-08-27",
            "router_engine": "work_contexts/engine.py",
            "collections": [
                {
                    "id": "work",
                    "mount": "work_contexts",
                    "entry_path": "README.md",
                    "registry_path": "contexts.registry.json",
                    "source_policy": "gitlink",
                    "summary": "Synthetic public work knowledge.",
                    "triggers": [
                        "work",
                        "backend retrieval",
                        "后端检索",
                        "agent memory",
                        "mcp",
                        "multi-hop",
                        "多跳",
                    ],
                    "non_triggers": [],
                    "routing_profile": {
                        "terms": ["work", "backend", "agent", "mcp"],
                        "boost_groups": [],
                    },
                    "status": "active",
                    "searchable": True,
                    "privacy_class": "portable",
                    "sync_targets": {"codex": True, "github": True},
                },
                {
                    "id": "personal_knowledge",
                    "mount": "personal_knowledge",
                    "entry_path": "README.md",
                    "registry_path": "contexts.registry.json",
                    "source_policy": "parent_tree",
                    "summary": "Synthetic public personal methods.",
                    "triggers": ["nutrition", "body composition", "营养", "体成分"],
                    "non_triggers": [],
                    "routing_profile": {
                        "terms": ["nutrition", "body composition", "营养", "体成分"],
                        "boost_groups": [],
                    },
                    "status": "active",
                    "searchable": True,
                    "privacy_class": "portable",
                    "sync_targets": {"codex": True, "github": True},
                },
            ],
        }
        cls.write_json(cls.fixture_root / "knowledge_collections.registry.json", registry)
        (cls.fixture_root / "memory_index.md").write_text(
            "# Synthetic Memory Index\n",
            encoding="utf-8",
        )
        evals = cls.fixture_root / "evals"
        evals.mkdir()
        (evals / "knowledge_router_cases.csv").write_text(
            "id,user_request,expected_decision,expected_collection,expected_context,expected_first_file\n",
            encoding="utf-8",
        )
        cls._write_projection_sources()
        cls.git(cls.fixture_root, "add", ".")
        cls.git(cls.fixture_root, "commit", "-m", "synthetic parent authority")
        cls.child_revision = child_revision
        cls.parent_revision = cls.git(cls.fixture_root, "rev-parse", "HEAD")
        cls._make_graph_fixture()

    @classmethod
    def _write_projection_sources(cls) -> None:
        sources = {
            "core/rule.md": (
                "---\nid: durable-rule\nscope: global\nstatus: active\nprivacy_class: public\n---\n\n"
                "# Deterministic Review\n\nUse deterministic review gates for durable work.\n"
            ),
            "platform/codex.md": (
                "---\nid: platform-codex\nscope: platform\napplies_to: codex\nstatus: active\n"
                "privacy_class: public\n---\n\n# Codex Adapter\n\nUse the Codex adapter.\n"
            ),
            "learnings/expired.md": (
                "---\nid: learning-expired\nscope: learning\nstatus: active\nprivacy_class: public\n"
                "valid_to: 2020-01-01T00:00:00Z\n---\n\nExpired lifecycle marker.\n"
            ),
            "learnings/superseded.md": (
                "---\nid: learning-superseded\nscope: learning\nstatus: superseded\n"
                "privacy_class: public\n---\n\nSuperseded lifecycle marker.\n"
            ),
            "learnings/deleted.md": (
                "---\nid: learning-deleted\nscope: learning\nstatus: active\nprivacy_class: public\n"
                "deleted: true\n---\n\nDeleted lifecycle marker.\n"
            ),
            "learnings/tombstoned.md": (
                "---\nid: learning-tombstoned\nscope: learning\nstatus: active\nprivacy_class: public\n"
                "---\n\nTombstoned lifecycle marker.\n"
            ),
        }
        for relative, content in sources.items():
            path = cls.fixture_root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        tombstoned = (cls.fixture_root / "learnings/tombstoned.md").read_bytes()
        cls.write_json(
            cls.fixture_root / "lifecycle/tombstones/learning-tombstoned.json",
            {
                "schema_version": 1,
                "tombstone_id": "tomb-learning-tombstoned",
                "item_id": "learning-tombstoned",
                "authority_path": "learnings/tombstoned.md",
                "authority_sha256": hashlib.sha256(tombstoned).hexdigest(),
                "reason": "synthetic explicit deletion",
                "approval_receipt": "synthetic-public-receipt",
                "created_at": "2026-08-27T00:00:00Z",
                "runtime_purge_binding": {
                    "schema_version": 1,
                    "scope": "whole_sessions",
                    "target_candidate_ids": ["cand_" + "a" * 64],
                    "session_selector_digests": ["b" * 64],
                },
            },
        )

    @classmethod
    def _make_graph_fixture(cls) -> None:
        graph_id = "work-contexts-routing"
        graph_dir = cls.graph_root / graph_id / "graphify-out"
        extraction = {
            "graph_id": graph_id,
            "nodes": [
                {
                    "id": "context_backend_retrieval_information_flow",
                    "kind": "context",
                    "status": "active",
                    "label": "Backend Retrieval",
                    "summary": "Ordered path multi-hop retrieval.",
                    "entry_path": "backend_retrieval_information_flow/README.md",
                    "triggers": ["backend retrieval", "后端检索"],
                    "routing_terms": ["multi-hop", "ordered path"],
                    "source_file": "contexts.registry.json",
                    "source_location": "contexts[1]",
                },
                {
                    "id": "context_mcp",
                    "kind": "context",
                    "status": "active",
                    "label": "MCP",
                    "summary": "Tool authorization resources.",
                    "entry_path": "mcp/README.md",
                    "triggers": ["mcp", "工具授权资源"],
                    "routing_terms": ["tool authorization"],
                    "source_file": "contexts.registry.json",
                    "source_location": "contexts[2]",
                },
            ],
            "edges": [
                {
                    "id": "edge-backend-mcp",
                    "source": "context_backend_retrieval_information_flow",
                    "target": "context_mcp",
                    "relation": "uses",
                    "confidence": "EXTRACTED",
                    "source_file": "contexts.registry.json",
                    "source_location": "edges[0]",
                }
            ],
        }
        cls.write_json(graph_dir / "source_extraction.json", extraction)
        fingerprint = hashlib.sha256(
            json.dumps(extraction, ensure_ascii=False, sort_keys=True).encode("utf-8")
        ).hexdigest()
        cls.write_json(
            graph_dir / "health.json",
            {
                "graph_id": graph_id,
                "source_revision": cls.child_revision,
                "source_dirty": False,
                "source_fingerprint": fingerprint,
                "hard_gates": {"schema": True, "revision": True},
            },
        )

    @classmethod
    def _make_layered_fixture(cls) -> None:
        core = cls.codex_home / "memories/core"
        platform = cls.codex_home / "memories/platform"
        core.mkdir(parents=True)
        platform.mkdir(parents=True)
        (core / "policy.md").write_text(
            "Synthetic bilingual policy: 权限 scope privacy authority.\n",
            encoding="utf-8",
        )
        (platform / "codex.md").write_text(
            "Mixed language Codex 检索 policy.\n",
            encoding="utf-8",
        )

    @classmethod
    def _recall_policy(cls) -> dict[str, object]:
        return {
            "schema_version": 1,
            "scopes": ["global", "platform", "learning"],
            "applies_to": "codex",
            "as_of": "2026-08-27T00:00:00Z",
            "allowed_authorization_states": ["not_required", "user_approved"],
            "allowed_provenance_trust": ["canonical_legacy", "current_source_validated"],
            "allowed_privacy_classes": ["public"],
            "high_stakes": False,
            "private_profile": False,
            "eligible_lifecycles": ["active", "legacy"],
            "require_source_revision_match": True,
            "require_content_hash_match": True,
            "require_canonical_relevance": True,
            "exclude_tombstoned": True,
            "exclude_deleted": True,
        }

    @classmethod
    def _build_projection(cls) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        try:
            from memory_control_plane.projection import MemoryProjection
            from memory_control_plane.recall_policy import RecallPolicy

            projection = MemoryProjection(
                repository=cls.fixture_root,
                index_path=cls.projection_path,
                authority_roots=("core", "platform", "learnings"),
            )
            projection.build(context=RecallPolicy.from_mapping(cls._recall_policy()))
        finally:
            sys.path.remove(str(ROOT / "scripts"))

    def run_driver(self, code_root: Path, payload: dict[str, object]) -> dict[str, object]:
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(code_root / "scripts")
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        completed = subprocess.run(
            [sys.executable, "-c", DRIVER],
            cwd=self.fixture_root,
            env=environment,
            input=json.dumps(payload, ensure_ascii=False),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        try:
            return json.loads(completed.stdout)
        except json.JSONDecodeError as error:
            self.fail(f"differential driver emitted invalid JSON: {error}: {completed.stdout!r}")

    def normalized_case(self, payload: dict[str, object]) -> dict[str, object]:
        replacements = {
            str(self.fixture_root): "$AUTHORITY",
            str(self.codex_home): "$CODEX_HOME",
            str(self.graph_root): "$GRAPH_ROOT",
            str(self.projection_path): "$PROJECTION",
            str(self.hybrid_projection_path): "$HYBRID_PROJECTION",
        }

        def replace(value: object) -> object:
            if isinstance(value, dict):
                return {key: replace(item) for key, item in value.items()}
            if isinstance(value, (list, tuple)):
                return [replace(item) for item in value]
            return replacements.get(value, value) if isinstance(value, str) else value

        normalized = replace(payload)
        assert isinstance(normalized, dict)
        return normalized

    def assert_baseline_digest(
        self,
        payload: dict[str, object],
        value: object,
        *,
        volatile_keys: frozenset[str] = frozenset(),
    ) -> None:
        def stable(item: object) -> object:
            if isinstance(item, dict):
                return {
                    key: stable(child)
                    for key, child in item.items()
                    if key not in volatile_keys
                }
            if isinstance(item, list):
                return [stable(child) for child in item]
            return item

        signature = {
            "baseline": BASELINE_COMMIT,
            "payload": self.normalized_case(payload),
            "volatile_keys": sorted(volatile_keys),
        }
        case_id = hashlib.sha256(
            json.dumps(signature, ensure_ascii=False, sort_keys=True).encode("utf-8")
        ).hexdigest()[:20]
        digest = hashlib.sha256(
            json.dumps(stable(value), ensure_ascii=False, sort_keys=True).encode("utf-8")
        ).hexdigest()
        if CAPTURE_BASELINE:
            print(f"BASELINE_DIGEST {case_id} {digest}")
            return
        self.assertIn(case_id, EXPECTED_BASELINE_DIGESTS, f"unfrozen case: {case_id}")
        self.assertEqual(digest, EXPECTED_BASELINE_DIGESTS[case_id])

    def assert_differential(
        self,
        payload: dict[str, object],
        *,
        volatile_keys: frozenset[str] = frozenset(),
    ) -> dict[str, object]:
        candidate = self.run_driver(ROOT, payload)
        if self.baseline_available:
            baseline = self.run_driver(self.baseline_root, payload)

            def stable(item: object) -> object:
                if isinstance(item, dict):
                    return {
                        key: stable(child)
                        for key, child in item.items()
                        if key not in volatile_keys
                    }
                if isinstance(item, list):
                    return [stable(child) for child in item]
                return item

            self.assertEqual(stable(candidate), stable(baseline))
            self.assert_baseline_digest(
                payload,
                baseline,
                volatile_keys=volatile_keys,
            )
        else:
            self.assert_baseline_digest(
                payload,
                candidate,
                volatile_keys=volatile_keys,
            )
        return candidate

    def options(self, **overrides: object) -> dict[str, object]:
        values: dict[str, object] = {
            "root": str(self.fixture_root),
            "codex_home": str(self.codex_home),
            "graph_root": str(self.graph_root),
            "limit": 5,
        }
        values.update(overrides)
        return values

    def test_legacy_router_matches_baseline_across_routing_and_safety_cases(self) -> None:
        for query in (
            "backend retrieval ordered path multi-hop",
            "中文后端检索多跳",
            "MCP 工具授权资源",
            "latest agent memory policy",
            "nutrition 体成分",
            "no-result 不存在",
            "read my personal memories",
        ):
            with self.subTest(query=query):
                result = self.assert_differential(
                    {
                        "call": "function",
                        "module": "knowledge_router",
                        "function": "route_knowledge",
                        "query": query,
                        "options": {
                            "root": str(self.fixture_root),
                            "read_selector": "first",
                        },
                    }
                )
                self.assertTrue(result["ok"])

    def test_v2_router_matches_baseline_for_expanded_context_routing(self) -> None:
        for query in (
            "backend_retrieval_information_flow",
            "tool authorization resources",
            "智能体长期记忆如何检索事实",
            "Do not use MCP; use backend retrieval multi-hop",
            "latest agent memory policy",
            "no-result 不存在",
            "读取我的 personal memories",
        ):
            with self.subTest(query=query):
                result = self.assert_differential(
                    {
                        "call": "function",
                        "module": "retrieval_v2_knowledge_router",
                        "function": "route_knowledge",
                        "query": query,
                        "options": {
                            "root": str(self.fixture_root),
                            "read_selector": "first",
                        },
                    }
                )
                self.assertTrue(result["ok"])

    def test_router_error_semantics_match_baseline(self) -> None:
        for module in ("knowledge_router", "retrieval_v2_knowledge_router"):
            for query in (None, ""):
                with self.subTest(module=module, query=query):
                    result = self.assert_differential(
                        {
                            "call": "function",
                            "module": module,
                            "function": "route_knowledge",
                            "query": query,
                            "options": {"root": str(self.fixture_root)},
                        }
                    )
                    self.assertFalse(result["ok"])

    def test_public_source_resolution_helpers_preserve_profile_isolation(self) -> None:
        for module in ("knowledge_router", "retrieval_v2_knowledge_router"):
            for plural, collection_id in ((True, None), (False, "work")):
                with self.subTest(module=module, plural=plural):
                    result = self.assert_differential(
                        {
                            "call": "resolve_sources",
                            "module": module,
                            "root": str(self.fixture_root),
                            "plural": plural,
                            "collection_id": collection_id,
                            "poison_path": True,
                        }
                    )
                    if module == "knowledge_router":
                        self.assertTrue(result["ok"])
                    else:
                        self.assertFalse(result["ok"])

    def test_legacy_router_public_namespace_matches_baseline(self) -> None:
        result = self.assert_differential(
            {
                "call": "public_names",
                "module": "knowledge_router",
            }
        )
        self.assertIn("route_knowledge", result["value"])

    def test_legacy_access_matches_baseline_for_domain_policy_and_lifecycle(self) -> None:
        domain = self.options(
            router_root=str(self.fixture_root),
            read_selector="first",
            expand_graph=True,
        )
        for query in (
            "backend retrieval ordered path multi-hop",
            "中文后端检索多跳",
            "no-result 不存在",
            "read my personal memories",
        ):
            with self.subTest(mode="domain", query=query):
                result = self.assert_differential(
                    {
                        "call": "function",
                        "module": "knowledge_access",
                        "function": "access_knowledge",
                        "query": query,
                        "options": {**domain, "mode": "domain"},
                    }
                )
                self.assertTrue(result["ok"])

        for query in (
            "deterministic review",
            "expired lifecycle marker",
            "superseded lifecycle marker",
            "deleted lifecycle marker",
            "tombstoned lifecycle marker",
        ):
            with self.subTest(mode="durable", query=query):
                result = self.assert_differential(
                    {
                        "call": "function",
                        "module": "knowledge_access",
                        "function": "access_knowledge",
                        "query": query,
                        "options": self.options(
                            mode="durable",
                            router_root=str(self.fixture_root),
                            projection_path=str(self.projection_path),
                            hybrid_projection_path=str(self.hybrid_projection_path),
                            recall_policy=self._recall_policy(),
                        ),
                    }
                )
                self.assertTrue(result["ok"])

        for query in ("权限 privacy authority", "missing policy phrase"):
            with self.subTest(mode="policy", query=query):
                result = self.assert_differential(
                    {
                        "call": "function",
                        "module": "knowledge_access",
                        "function": "access_knowledge",
                        "query": query,
                        "options": self.options(mode="policy", strategy="all"),
                    }
                )
                self.assertTrue(result["ok"])

    def test_v2_access_matches_baseline_for_live_graph_and_durable_lifecycle(self) -> None:
        for query in (
            "backend retrieval ordered path multi-hop",
            "中文后端检索多跳",
            "tool authorization resources",
            "no-result 不存在",
            "read my personal memories",
        ):
            with self.subTest(mode="domain", query=query):
                result = self.assert_differential(
                    {
                        "call": "function",
                        "module": "retrieval_v2_knowledge_access",
                        "function": "access_knowledge",
                        "query": query,
                        "options": self.options(
                            mode="domain",
                            read_selector="first",
                            expand_graph=True,
                        ),
                    }
                )
                self.assertTrue(result["ok"])

        for query in (
            "deterministic review",
            "expired lifecycle marker",
            "superseded lifecycle marker",
            "deleted lifecycle marker",
            "tombstoned lifecycle marker",
        ):
            with self.subTest(mode="durable", query=query):
                result = self.assert_differential(
                    {
                        "call": "function",
                        "module": "retrieval_v2_knowledge_access",
                        "function": "access_knowledge",
                        "query": query,
                        "options": self.options(
                            mode="durable",
                            projection_path=str(self.projection_path),
                            recall_scopes=("global", "platform", "learning"),
                        ),
                    }
                )
                self.assertTrue(result["ok"])

    def test_progressive_bootstrap_matches_baseline(self) -> None:
        payload = {
            "call": "progressive",
            "query": "backend retrieval ordered path multi-hop",
            "options": self.options(
                mode="domain",
                read_selector="first",
                expand_graph=False,
                allowed_scopes=("work",),
            ),
        }
        # These are the sole normalized fields: two subprocesses cannot share
        # the same wall-clock duration. The attempted-call, candidate,
        # character, round, result, and evidence budgets remain byte-for-byte.
        result = self.assert_differential(
            payload,
            volatile_keys=frozenset({"elapsed_ms", "latency_ms"}),
        )
        self.assertTrue(result["ok"])

    def test_access_error_semantics_match_baseline(self) -> None:
        for module in ("knowledge_access", "retrieval_v2_knowledge_access"):
            for query, overrides in (
                (None, {}),
                ("query", {"mode": "unsupported"}),
                ("query", {"limit": 0}),
            ):
                with self.subTest(module=module, query=query, overrides=overrides):
                    result = self.assert_differential(
                        {
                            "call": "function",
                            "module": module,
                            "function": "access_knowledge",
                            "query": query,
                            "options": self.options(**overrides),
                        }
                    )
                    self.assertFalse(result["ok"])

    def run_cli(self, code_root: Path, relative: str, *arguments: str) -> tuple[int, str, str]:
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(code_root / "scripts")
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        completed = subprocess.run(
            [sys.executable, str(code_root / relative), *arguments],
            cwd=self.fixture_root,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        return completed.returncode, completed.stdout, completed.stderr

    def test_original_script_cli_contracts_match_baseline(self) -> None:
        cases = (
            ("scripts/knowledge_router.py", ("--help",)),
            ("scripts/retrieval_v2_knowledge_router.py", ("--help",)),
            ("scripts/knowledge_access.py", ("--help",)),
            ("scripts/knowledge_access.py", ()),
            ("scripts/knowledge_access.py", ("",)),
            ("scripts/retrieval_v2_knowledge_access.py", ("--help",)),
            ("scripts/retrieval_v2_knowledge_access.py", ()),
            ("scripts/retrieval_v2_knowledge_access.py", ("",)),
        )
        for relative, arguments in cases:
            with self.subTest(relative=relative, arguments=arguments):
                payload: dict[str, object] = {
                    "call": "cli",
                    "relative": relative,
                    "arguments": arguments,
                }
                candidate = self.run_cli(ROOT, relative, *arguments)
                if self.baseline_available:
                    baseline = self.run_cli(self.baseline_root, relative, *arguments)
                    self.assertEqual(candidate, baseline)
                    self.assert_baseline_digest(payload, baseline)
                else:
                    self.assert_baseline_digest(payload, candidate)


if __name__ == "__main__":
    unittest.main()
