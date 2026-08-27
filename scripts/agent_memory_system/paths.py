"""Single source of truth for the local Agent Memory runtime paths."""

from __future__ import annotations

from pathlib import Path


MEMORIES_ROOT = Path(__file__).resolve().parents[2]
CODEX_HOME = MEMORIES_ROOT.parent
INDEX_ROOT = CODEX_HOME / "memory-sidecar" / "indexes"
RUNTIME_ROOT = CODEX_HOME / "memory-sidecar" / "agent-memory-v1"
STATE_PATH = RUNTIME_ROOT / "agent-memory.sqlite"
AUTHORITY_INDEX_PATH = INDEX_ROOT / "memory-control-v1.sqlite"
HYBRID_INDEX_PATH = INDEX_ROOT / "agent-memory-hybrid-v1.sqlite"
EMBEDDING_CACHE_PATH = RUNTIME_ROOT / "embedding-cache"
EMBEDDING_HELPER_PATH = MEMORIES_ROOT / "scripts" / "agent_memory_embedding.swift"
