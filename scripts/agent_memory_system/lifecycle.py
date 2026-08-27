"""Deterministic lifecycle proposals over source-bound memory candidates.

The resolver never authorizes or deletes anything.  It converts durable
candidate relations plus explicit expiry/tombstone metadata into a bounded
set of proposed actions for the existing governance plane.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import re
from typing import Any, Mapping, Sequence, TYPE_CHECKING
import unicodedata

if TYPE_CHECKING:
    from .store import AgentMemoryStore


@dataclass(frozen=True)
class LifecycleResolution:
    actions: list[dict[str, str]]
    active: list[str]
    expired: list[str]
    deletion_propagated: bool


class LifecycleResolver:
    """Resolve candidate state without changing canonical authority."""

    def resolve_records(
        self,
        *,
        existing: Sequence[Mapping[str, Any]],
        incoming: Sequence[Mapping[str, Any]],
        now: datetime,
    ) -> Mapping[str, Any]:
        """Resolve externally sourced records into proposal-only actions.

        This public seam is intentionally independent of a particular runtime
        store so migrations, recovery tools, and reproducible harnesses can
        exercise the same lifecycle policy.  It never mutates Markdown or
        authorizes a proposed durable change.
        """
        if now.tzinfo is None:
            raise ValueError("now must be timezone-aware")
        stamp = now.astimezone(timezone.utc)
        classifications: list[dict[str, str]] = []
        actions: list[dict[str, str]] = []
        expired_existing: set[str] = set()
        for raw in existing:
            old = dict(raw)
            old_id = str(old.get("id") or "")
            expiry = _parse_date(old.get("valid_until"))
            if (
                old_id
                and expiry is not None
                and expiry <= stamp
                and old.get("lifecycle") == "active"
                and old.get("tombstone") is not True
            ):
                actions.append({
                    "op": "expire", "target": old_id, "by": old_id,
                    "reason": "existing valid_until reached evaluation time",
                })
                expired_existing.add(old_id)
        active_existing = [
            dict(old) for old in existing
            if str(old.get("id") or "") not in expired_existing
            and old.get("lifecycle") == "active"
            and old.get("tombstone") is not True
        ]
        for raw in incoming:
            item = dict(raw)
            identifier = str(item.get("id") or "")
            memory_class = str(item.get("memory_class") or "no_op")
            claim = str(item.get("claim") or "")
            scope = str(item.get("scope") or "")
            if not identifier:
                continue
            classifications.append({"id": identifier, "memory_class": memory_class})
            expiry = _parse_date(item.get("valid_until"))
            expired = expiry is not None and expiry <= stamp
            deletion = item.get("deletion_requested") is True
            if expired:
                actions.append({
                    "op": "expire", "target": identifier, "by": identifier,
                    "reason": "valid_until precedes evaluation time",
                })
                continue
            if deletion:
                target_id = str(item.get("deletion_target_id") or "")
                target = next(
                    (old for old in active_existing if str(old.get("id")) == target_id),
                    None,
                )
                if target is None:
                    actions.append({
                        "op": "no_op", "target": identifier, "by": identifier,
                        "reason": "deletion target is not active",
                    })
                    continue
                target_scope = str(target.get("scope") or "")
                if (
                    str(target.get("memory_class") or "")
                    in {"preference", "principle", "workflow"}
                    and not target_scope.startswith("task:")
                ):
                    actions.append({
                        "op": "require_authorization", "target": identifier,
                        "by": identifier,
                        "reason": "high-impact durable deletion requires explicit authorization",
                    })
                actions.append({
                    "op": "tombstone", "target": target_id, "by": identifier,
                    "reason": "deletion_requested=true",
                })
                continue

            exact = next(
                (
                    old for old in active_existing
                    if str(old.get("scope")) == scope
                    and str(old.get("memory_class")) == memory_class
                    and _normalized_claim(old.get("claim")) == _normalized_claim(claim)
                ),
                None,
            )
            related = next(
                (
                    old for old in active_existing
                    if str(old.get("scope")) == scope
                    and str(old.get("memory_class")) == memory_class
                    and _record_claim_tokens(str(old.get("claim") or ""))
                    & _record_claim_tokens(claim)
                ),
                None,
            )
            if exact is not None:
                actions.append({
                    "op": "deduplicate", "target": str(exact["id"]),
                    "by": identifier, "reason": "same normalized claim and scope",
                })
            elif related is not None:
                operation = (
                    "update"
                    if re.search(r"(?:改为|改成|更新|\bnow\b|\binstead\b)", claim, re.IGNORECASE)
                    else "conflict"
                )
                actions.append({
                    "op": operation,
                    "target": str(related["id"]),
                    "by": identifier,
                    "reason": (
                        "newer compatible claim in same scope"
                        if operation == "update"
                        else "incompatible claim in same scoped slot"
                    ),
                })
            else:
                actions.append({
                    "op": "create", "target": identifier, "by": identifier,
                    "reason": "new scoped claim",
                })

            if (
                exact is None
                and memory_class in {"preference", "principle", "workflow"}
                and not scope.startswith("task:")
            ):
                actions.append({
                    "op": "require_authorization", "target": identifier,
                    "by": identifier,
                    "reason": "high-impact durable memory requires explicit authorization",
                })

        unique = {
            (action["op"], action["target"], action["by"], action["reason"]): action
            for action in actions
        }
        return {
            "classifications": sorted(classifications, key=lambda value: value["id"]),
            "actions": sorted(
                unique.values(),
                key=lambda value: (
                    value["op"], value["target"], value["by"], value["reason"]
                ),
            ),
        }

    def resolve_store(
        self,
        store: "AgentMemoryStore",
        *,
        now: datetime,
        session_id: str | None = None,
        external_ids: Mapping[str, str] | None = None,
        incoming_ids: set[str] | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> LifecycleResolution:
        """Resolve the durable product store without a harness translation."""
        all_candidates = store.list_candidates()
        relations = store.list_relations(session_id=session_id)
        selected_ids = {
            str(row["candidate_id"])
            for row in all_candidates
            if session_id is None or row.get("session_id") == session_id
        }
        related_ids = set(selected_ids)
        for relation in relations:
            related_ids.add(str(relation.get("source_candidate_id", "")))
            related_ids.add(str(relation.get("target_candidate_id", "")))
        candidates = [
            row for row in all_candidates
            if str(row["candidate_id"]) in related_ids
        ]
        identifiers = dict(
            external_ids
            or {
                str(row["candidate_id"]): str(row["candidate_id"])
                for row in candidates
            }
        )
        incoming = set(
            incoming_ids
            or {
                identifiers[str(row["candidate_id"])]
                for row in candidates
                if str(row["candidate_id"]) in identifiers
                and (session_id is None or str(row["candidate_id"]) in selected_ids)
            }
        )
        lifecycle_metadata: dict[str, Any] = dict(metadata or {})
        records = dict(lifecycle_metadata.get("records", {}))
        for row in candidates:
            external = identifiers.get(str(row["candidate_id"]))
            if external and external not in records:
                records[external] = {"expires_at": row.get("expires_at")}
        lifecycle_metadata["records"] = records
        return self.resolve(
            candidates=candidates,
            relations=relations,
            external_ids=identifiers,
            incoming_ids=incoming,
            metadata=lifecycle_metadata,
            now=now,
        )

    def resolve(
        self,
        *,
        candidates: Sequence[Mapping[str, Any]],
        relations: Sequence[Mapping[str, Any]],
        external_ids: Mapping[str, str],
        incoming_ids: set[str],
        metadata: Mapping[str, Any],
        now: datetime,
    ) -> LifecycleResolution:
        if now.tzinfo is None:
            raise ValueError("now must be timezone-aware")
        stamp = now.astimezone(timezone.utc)
        records = metadata.get("records", {})
        records = records if isinstance(records, Mapping) else {}
        tombstones = {str(value) for value in metadata.get("tombstones", ())}
        delete_source = metadata.get("delete_source")
        duplicate_pairs = metadata.get("duplicate_pairs", ())

        actions: list[dict[str, str]] = []
        inactive: set[str] = set()
        expired: list[str] = []
        deleted_lineage: set[str] = set(tombstones)

        for external_id, record in records.items():
            if not isinstance(record, Mapping):
                continue
            expiry = _parse_date(record.get("expires_at"))
            # ``valid_to``/``expires_at`` is an exclusive upper bound: the
            # record is no longer eligible at the boundary itself.
            if expiry is not None and expiry <= stamp:
                identifier = str(external_id)
                actions.append({"op": "expire", "target": identifier})
                inactive.add(identifier)
                expired.append(identifier)

        for target in sorted(tombstones):
            actions.append({"op": "tombstone", "target": target})
            inactive.add(target)

        if isinstance(duplicate_pairs, Sequence) and not isinstance(duplicate_pairs, (str, bytes)):
            for pair in duplicate_pairs:
                if not isinstance(pair, Sequence) or isinstance(pair, (str, bytes)) or len(pair) != 2:
                    continue
                duplicate, original = str(pair[0]), str(pair[1])
                actions.append({"op": "deduplicate", "target": duplicate, "into": original})
                inactive.add(duplicate)

        candidate_by_id = {
            str(candidate.get("candidate_id", "")): candidate for candidate in candidates
        }
        for relation in sorted(
            relations,
            key=lambda value: _relation_order(value, candidate_by_id),
        ):
            relation_type = str(relation.get("relation_type", ""))
            source = external_ids.get(str(relation.get("source_candidate_id", "")))
            target = external_ids.get(str(relation.get("target_candidate_id", "")))
            if not source or not target:
                continue
            # A tombstone wins over later relation proposals.  Do not emit an
            # update/supersede action that a downstream consumer could apply
            # before it notices the deletion propagation.
            if target in deleted_lineage and source in incoming_ids:
                suppression = {
                    "op": "suppress_candidate",
                    "target": source,
                    "reason": "deleted_lineage",
                }
                if suppression not in actions:
                    actions.append(suppression)
                deleted_lineage.add(source)
                inactive.add(source)
                continue
            if relation_type == "duplicate":
                actions.append({"op": "deduplicate", "target": source, "into": target})
                inactive.add(source)
            elif relation_type == "conflict":
                actions.append({"op": relation_type, "target": target, "by": source})
                # Conflicts remain proposed but are not eligible for automatic
                # activation or recall until governance resolves them.
                inactive.add(source)
            elif relation_type in {"update", "supersede"}:
                actions.append({"op": relation_type, "target": target, "by": source})
                inactive.add(target)
            elif relation_type == "delete":
                actions.append({"op": "propagate_delete", "target": target})
                deleted_lineage.add(target)
                inactive.add(target)

            if target in deleted_lineage and source in incoming_ids:
                suppression = {
                    "op": "suppress_candidate",
                    "target": source,
                    "reason": "deleted_lineage",
                }
                if suppression not in actions:
                    actions.append(suppression)
                deleted_lineage.add(source)
                inactive.add(source)

        if isinstance(delete_source, str) and delete_source:
            actions.append({"op": "propagate_delete", "target": delete_source})

        active = []
        for candidate in candidates:
            candidate_id = str(candidate.get("candidate_id", ""))
            external = external_ids.get(candidate_id)
            if not external or external not in incoming_ids or external in inactive:
                continue
            if candidate.get("status") != "proposed" or candidate.get("memory_class") == "no_op":
                continue
            active.append(external)

        return LifecycleResolution(
            actions=_unique_actions(actions),
            active=list(dict.fromkeys(active)),
            expired=list(dict.fromkeys(expired)),
            deletion_propagated=bool(tombstones or delete_source or deleted_lineage),
        )


def _parse_date(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _normalized_claim(value: object) -> str:
    return " ".join(unicodedata.normalize("NFC", str(value)).casefold().split())


def _record_claim_tokens(value: str) -> set[str]:
    folded = _normalized_claim(value)
    tokens = list(re.findall(r"[a-z0-9_./:-]+", folded))
    for run in re.findall(r"[\u3400-\u9fff]{2,}", folded):
        tokens.extend(
            run[offset : offset + width]
            for width in (2, 3)
            for offset in range(0, len(run) - width + 1)
        )
    stop = {"改为", "改成", "更新为", "删除", "忘记", "移除", "现在", "新的"}
    return {token for token in tokens if token not in stop}


def _unique_actions(actions: Sequence[Mapping[str, str]]) -> list[dict[str, str]]:
    seen: set[tuple[tuple[str, str], ...]] = set()
    result: list[dict[str, str]] = []
    for action in actions:
        item = {str(key): str(value) for key, value in action.items()}
        signature = tuple(sorted(item.items()))
        if signature in seen:
            continue
        seen.add(signature)
        result.append(item)
    return result


def _relation_order(
    relation: Mapping[str, Any],
    candidates: Mapping[str, Mapping[str, Any]],
) -> tuple[str, str, int, str, int, str]:
    source_id = str(relation.get("source_candidate_id", ""))
    source = candidates.get(source_id, {})
    priority = {
        "duplicate": 0,
        "conflict": 1,
        "update": 2,
        "supersede": 3,
        "delete": 4,
    }.get(str(relation.get("relation_type", "")), 9)
    return (
        str(source.get("created_at") or relation.get("created_at") or ""),
        str(source.get("source_path") or ""),
        int(source.get("source_line") or 0),
        source_id,
        priority,
        str(relation.get("relation_id") or ""),
    )
