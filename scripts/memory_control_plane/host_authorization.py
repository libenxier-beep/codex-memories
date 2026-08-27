from __future__ import annotations

import hashlib
import os
import re
import stat
import subprocess
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from .model import canonical_json, digest_object


HOST_AUTHORIZATION_NAMESPACE = "codex-memory-control-v1"
MAX_ALLOWED_SIGNERS_BYTES = 64 * 1024
MAX_SIGNATURE_BYTES = 16 * 1024
MAX_CAPABILITY_LIFETIME = timedelta(minutes=15)
MAX_CLOCK_SKEW = timedelta(seconds=30)
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_IDENTITY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9@._+-]{0,254}$")
_NONCE = re.compile(r"^[A-Za-z0-9_-]{32,128}$")
_PHASES = frozenset({"authorize", "apply", "recover"})


def _parse_timestamp(value: object) -> datetime:
    if not isinstance(value, str) or not value:
        raise ValueError("host capability timestamp is invalid")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        raise ValueError("host capability timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)


def _authorization_binding(request: Mapping[str, Any]) -> dict[str, Any]:
    binding = dict(request)
    binding.pop("phase", None)
    binding.pop("approval_id", None)
    return binding


def build_host_authorization_statement(
    authorization_request: Mapping[str, Any],
    *,
    signer_identity: str,
    nonce: str,
    issued_at: str,
    expires_at: str,
    authorized_phases: Sequence[str] = ("authorize", "apply"),
) -> dict[str, Any]:
    """Build the canonical unsigned statement that an external host signs."""

    if authorization_request.get("phase") != "authorize":
        raise ValueError("the signed authorization request must be in the authorize phase")
    if _IDENTITY.fullmatch(signer_identity) is None:
        raise ValueError("host signer identity is invalid")
    if _NONCE.fullmatch(nonce) is None:
        raise ValueError("host capability nonce is invalid")
    phases = list(authorized_phases)
    if (
        not phases
        or len(phases) != len(set(phases))
        or set(phases) - _PHASES
        or "authorize" not in phases
    ):
        raise ValueError("host capability phases are invalid")
    issued = _parse_timestamp(issued_at)
    expires = _parse_timestamp(expires_at)
    if issued >= expires or expires - issued > MAX_CAPABILITY_LIFETIME:
        raise ValueError("host capability validity window is invalid")
    body: dict[str, Any] = {
        "schema_version": 1,
        "namespace": HOST_AUTHORIZATION_NAMESPACE,
        "signer_identity": signer_identity,
        "nonce": nonce,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "authorized_phases": phases,
        "authorization_request": dict(authorization_request),
    }
    return {**body, "capability_id": "cap_" + digest_object(body)}


class SshHostAuthorizationVerifier:
    """Verify a bounded OpenSSH signed host capability against a pinned trust file."""

    def __init__(
        self,
        *,
        allowed_signers_path: Path,
        allowed_signers_sha256: str,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        if _DIGEST.fullmatch(allowed_signers_sha256) is None:
            raise ValueError("allowed signers digest is invalid")
        self.allowed_signers_path = Path(allowed_signers_path)
        self.allowed_signers_sha256 = allowed_signers_sha256
        self.now = now or (lambda: datetime.now(timezone.utc))

    def _read_allowed_signers(self) -> bytes:
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(str(self.allowed_signers_path), flags)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_ALLOWED_SIGNERS_BYTES:
                raise ValueError("allowed signers must be a bounded regular file")
            with os.fdopen(descriptor, "rb", closefd=False) as handle:
                raw = handle.read(MAX_ALLOWED_SIGNERS_BYTES + 1)
        finally:
            os.close(descriptor)
        if len(raw) > MAX_ALLOWED_SIGNERS_BYTES:
            raise ValueError("allowed signers file exceeds its bounded size")
        if hashlib.sha256(raw).hexdigest() != self.allowed_signers_sha256:
            raise ValueError("allowed signers digest mismatch")
        return raw

    def __call__(self, capability: object, request: Mapping[str, Any]) -> str | None:
        if not isinstance(capability, dict) or set(capability) != {
            "schema_version",
            "statement",
            "signature",
        }:
            raise ValueError("host capability envelope is invalid")
        if capability.get("schema_version") != 1:
            raise ValueError("host capability schema is invalid")
        statement = capability.get("statement")
        signature = capability.get("signature")
        if not isinstance(statement, dict) or set(statement) != {
            "schema_version",
            "namespace",
            "signer_identity",
            "nonce",
            "issued_at",
            "expires_at",
            "authorized_phases",
            "authorization_request",
            "capability_id",
        }:
            raise ValueError("host capability statement is invalid")
        if not isinstance(signature, str) or not (0 < len(signature.encode("ascii")) <= MAX_SIGNATURE_BYTES):
            raise ValueError("host capability signature is invalid")
        signer_identity = statement.get("signer_identity")
        nonce = statement.get("nonce")
        phases = statement.get("authorized_phases")
        signed_request = statement.get("authorization_request")
        if (
            statement.get("schema_version") != 1
            or statement.get("namespace") != HOST_AUTHORIZATION_NAMESPACE
            or not isinstance(signer_identity, str)
            or _IDENTITY.fullmatch(signer_identity) is None
            or not isinstance(nonce, str)
            or _NONCE.fullmatch(nonce) is None
            or not isinstance(phases, list)
            or not phases
            or len(phases) != len(set(phases))
            or set(phases) - _PHASES
            or "authorize" not in phases
            or not isinstance(signed_request, dict)
            or signed_request.get("phase") != "authorize"
        ):
            raise ValueError("host capability statement binding is invalid")
        body = dict(statement)
        capability_id = body.pop("capability_id", None)
        if capability_id != "cap_" + digest_object(body):
            raise ValueError("host capability identifier is invalid")
        issued = _parse_timestamp(statement.get("issued_at"))
        expires = _parse_timestamp(statement.get("expires_at"))
        current = self.now().astimezone(timezone.utc)
        if (
            issued >= expires
            or expires - issued > MAX_CAPABILITY_LIFETIME
            or issued > current + MAX_CLOCK_SKEW
            or current >= expires
        ):
            raise ValueError("host capability is outside its validity window")
        phase = request.get("phase")
        if phase not in phases:
            raise ValueError("host capability does not authorize this phase")
        if phase == "authorize":
            request_matches = dict(request) == signed_request
        else:
            request_matches = _authorization_binding(request) == _authorization_binding(signed_request)
        if not request_matches:
            raise ValueError("host capability does not bind this request")

        allowed_signers = self._read_allowed_signers()
        with tempfile.TemporaryDirectory(prefix="memory-host-auth-") as temporary:
            temporary_root = Path(temporary)
            allowed_path = temporary_root / "allowed_signers"
            signature_path = temporary_root / "capability.sig"
            allowed_path.write_bytes(allowed_signers)
            signature_path.write_text(signature, encoding="ascii")
            os.chmod(allowed_path, 0o600)
            os.chmod(signature_path, 0o600)
            completed = subprocess.run(
                [
                    "/usr/bin/ssh-keygen",
                    "-Y",
                    "verify",
                    "-f",
                    str(allowed_path),
                    "-I",
                    signer_identity,
                    "-n",
                    HOST_AUTHORIZATION_NAMESPACE,
                    "-s",
                    str(signature_path),
                ],
                input=canonical_json(statement),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env={"LANG": "C", "LC_ALL": "C"},
                timeout=5,
                check=False,
            )
        if completed.returncode != 0:
            raise ValueError("host capability signature verification failed")
        return "cap_" + digest_object(
            {
                "schema_version": 1,
                "statement_capability_id": capability_id,
                "allowed_signers_sha256": self.allowed_signers_sha256,
                "signer_identity": signer_identity,
                "namespace": HOST_AUTHORIZATION_NAMESPACE,
            }
        )
