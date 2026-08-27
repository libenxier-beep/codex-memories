from __future__ import annotations

import json
import os
import secrets
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

from .model import ControlPlaneError, canonical_json, digest_object


JSON_BEGIN = "<!-- BEGIN MEMORY CONTROL JSON -->\n```json\n"
JSON_END = "\n```\n<!-- END MEMORY CONTROL JSON -->\n"
MAX_CONTROL_ARTIFACT_BYTES = 2 * 1024 * 1024


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def render_artifact(kind: str, value: Mapping[str, Any]) -> bytes:
    title = "# Memory Control Plane: {}\n\n".format(kind)
    body = canonical_json(value).decode("utf-8")
    return (title + JSON_BEGIN + body + JSON_END).encode("utf-8")


def _parse_artifact_text(text: str, source: object, expected_kind: Optional[str]) -> Dict[str, Any]:
    if not text.startswith("# Memory Control Plane: ") or JSON_BEGIN not in text or not text.endswith(JSON_END):
        raise ControlPlaneError("ledger_corrupt", "control artifact framing is invalid: {}".format(source))
    heading, encoded = text.split(JSON_BEGIN, 1)
    kind = heading[len("# Memory Control Plane: ") :].strip()
    if expected_kind is not None and kind != expected_kind:
        raise ControlPlaneError("ledger_corrupt", "control artifact kind is invalid: {}".format(source))
    encoded = encoded[: -len(JSON_END)]
    try:
        value = json.loads(encoded)
    except json.JSONDecodeError as error:
        raise ControlPlaneError("ledger_corrupt", "control artifact JSON is invalid: {}".format(error))
    if not isinstance(value, dict):
        raise ControlPlaneError("ledger_corrupt", "control artifact must contain an object")
    return value


def parse_artifact(path: Path, expected_kind: Optional[str] = None) -> Dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise ControlPlaneError("ledger_corrupt", "cannot read control artifact {}: {}".format(path, error))
    return _parse_artifact_text(text, path, expected_kind)


def parse_artifact_at(
    directory_fd: int,
    filename: str,
    expected_kind: Optional[str] = None,
) -> Dict[str, Any]:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(filename, flags, dir_fd=directory_fd)
    except OSError as error:
        raise ControlPlaneError("ledger_corrupt", "cannot securely open control artifact") from error
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_CONTROL_ARTIFACT_BYTES:
            raise ControlPlaneError("ledger_corrupt", "control artifact is not a bounded regular file")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            raw = handle.read(MAX_CONTROL_ARTIFACT_BYTES + 1)
        if len(raw) > MAX_CONTROL_ARTIFACT_BYTES:
            raise ControlPlaneError("ledger_corrupt", "control artifact exceeds its bounded size")
        try:
            text = raw.decode("utf-8")
        except UnicodeError as error:
            raise ControlPlaneError("ledger_corrupt", "control artifact is not UTF-8") from error
    finally:
        os.close(descriptor)
    return _parse_artifact_text(text, filename, expected_kind)


def fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    descriptor = os.open(str(path), flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    prior_mode = mode
    if path.exists() and not path.is_symlink():
        prior_mode = stat.S_IMODE(path.stat().st_mode)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".memory-control-", dir=str(path.parent))
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, prior_mode)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(str(temporary), str(path))
        fsync_directory(path.parent)
    except BaseException:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise


def atomic_write_at(directory_fd: int, filename: str, data: bytes, mode: int = 0o600) -> None:
    if not filename or filename in {".", ".."} or "/" in filename or "\x00" in filename:
        raise ControlPlaneError("control_artifact_root_unsafe", "control artifact filename is invalid")
    prior_mode = mode
    try:
        info = os.stat(filename, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        if not stat.S_ISREG(info.st_mode):
            raise ControlPlaneError(
                "control_artifact_root_unsafe",
                "control artifact destination is not a regular file",
            )
        prior_mode = stat.S_IMODE(info.st_mode)
    temporary_name = ""
    descriptor = -1
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    for _attempt in range(32):
        temporary_name = ".memory-control-" + secrets.token_hex(16)
        try:
            descriptor = os.open(temporary_name, flags, prior_mode, dir_fd=directory_fd)
            break
        except FileExistsError:
            continue
    if descriptor < 0:
        raise ControlPlaneError("control_artifact_root_unsafe", "cannot allocate control artifact temp file")
    try:
        os.fchmod(descriptor, prior_mode)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            descriptor = -1
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(
            temporary_name,
            filename,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )
        os.fsync(directory_fd)
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary_name, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
        raise


def write_artifact(path: Path, kind: str, value: Mapping[str, Any]) -> None:
    atomic_write(path, render_artifact(kind, value))


def make_event(kind: str, data: Mapping[str, Any], events: List[Mapping[str, Any]]) -> Dict[str, Any]:
    previous_hash = events[-1]["event_hash"] if events else "0" * 64
    body: Dict[str, Any] = {
        "seq": len(events) + 1,
        "kind": kind,
        "timestamp": utc_now(),
        "data": dict(data),
        "prev_event_hash": previous_hash,
    }
    body["event_hash"] = digest_object(body)
    return body


def verify_event_chain(events: object) -> None:
    if not isinstance(events, list) or not events:
        raise ControlPlaneError("ledger_corrupt", "event chain is empty or invalid")
    previous_hash = "0" * 64
    for expected_seq, event in enumerate(events, 1):
        if not isinstance(event, dict):
            raise ControlPlaneError("ledger_corrupt", "event is not an object")
        if set(event) != {"seq", "kind", "timestamp", "data", "prev_event_hash", "event_hash"}:
            raise ControlPlaneError("ledger_corrupt", "event shape is invalid")
        if event["seq"] != expected_seq or event["prev_event_hash"] != previous_hash:
            raise ControlPlaneError("ledger_corrupt", "event sequence or previous hash is invalid")
        supplied_hash = event["event_hash"]
        unhashed = dict(event)
        del unhashed["event_hash"]
        if supplied_hash != digest_object(unhashed):
            raise ControlPlaneError("ledger_corrupt", "event hash is invalid")
        previous_hash = supplied_hash
