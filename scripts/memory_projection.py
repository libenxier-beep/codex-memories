#!/usr/bin/env python3
"""Build, inspect, query, or retention-plan the disposable memory projection."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime
from pathlib import Path

from memory_control_plane.projection import MemoryProjection, ProjectionError
from memory_control_plane.recall_policy import (
    load_recall_policy_file,
    verify_recall_request,
)
from knowledge_router import route_knowledge


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INDEX = ROOT.parent / "memory-sidecar" / "indexes" / "memory-control-v1.sqlite"


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    root.add_argument("--root", type=Path, default=ROOT)
    root.add_argument(
        "--router-root",
        type=Path,
        help="trusted committed router authority (defaults to --root)",
    )
    root.add_argument("--index", type=Path, default=DEFAULT_INDEX)
    commands = root.add_subparsers(dest="command", required=True)

    build = commands.add_parser("build")
    build.add_argument("--revision", default="HEAD")
    build.add_argument(
        "--recall-policy-file",
        "--policy-file",
        dest="policy_file",
        type=Path,
        required=True,
        help="RecallPolicy v1 JSON used to filter before index construction",
    )

    recall = commands.add_parser("recall")
    recall.add_argument("query", nargs="+")
    recall.add_argument("--limit", type=int, default=5)
    recall.add_argument(
        "--recall-policy-file",
        "--policy-file",
        dest="policy_file",
        type=Path,
        help="RecallPolicy v1 JSON (legacy alias: --policy-file)",
    )

    commands.add_parser("manifest")
    retention = commands.add_parser("retention-plan")
    retention.add_argument("--as-of", required=True)
    return root


def main() -> int:
    args = parser().parse_args()
    try:
        projection = MemoryProjection(
            repository=args.root.resolve(strict=True),
            index_path=args.index,
            authority_roots=("core", "platform", "learnings"),
        )
        if args.command == "build":
            policy = load_recall_policy_file(args.policy_file)
            result = projection.build(args.revision, context=policy)
        elif args.command == "recall":
            policy = None
            if args.policy_file is not None:
                policy = load_recall_policy_file(args.policy_file)
            query = " ".join(args.query)
            try:
                router_root = args.router_root or args.root
                route = route_knowledge(query, root=router_root, read_selector=None)
                request = verify_recall_request(
                    query,
                    policy,
                    route_result=route,
                    entry_point="projection_cli",
                    session_id="projection-cli:" + hashlib.sha256(
                        (
                            str(args.root.resolve(strict=False))
                            + "\0"
                            + str(router_root.resolve(strict=False))
                        ).encode("utf-8")
                    ).hexdigest(),
                )
            except Exception:
                result = {
                    "schema_version": 1,
                    "status": "abstain",
                    "reason": "query_classification_failed",
                    "matches": [],
                }
            else:
                result = projection.recall(
                    query,
                    context=request.policy,
                    limit=args.limit,
                )
        elif args.command == "manifest":
            result = projection.export_manifest()
        elif args.command == "retention-plan":
            result = projection.plan_retention(as_of=datetime.fromisoformat(args.as_of.replace("Z", "+00:00")))
        else:
            raise AssertionError(args.command)
    except (ProjectionError, OSError, ValueError) as error:
        print(json.dumps({"ok": False, "error": str(error)}, ensure_ascii=False))
        return 2
    print(json.dumps({"ok": True, "result": result}, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
