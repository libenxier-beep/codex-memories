"""Deterministic, local-only secret redaction before runtime persistence."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Mapping, Sequence


@dataclass(frozen=True)
class RedactionPolicy:
    """Configuration for the persistence boundary redactor.

    The default patterns intentionally target credential syntax and known token
    formats instead of generic high-entropy text.  That keeps ordinary hashes,
    opaque evidence references, prose about credentials, and source identities
    intact while still covering the forms most likely to appear in tool I/O.
    """

    enabled: bool = True
    replacement_prefix: str = "[REDACTED:"
    replacement_suffix: str = "]"
    additional_sensitive_keys: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.replacement_prefix or not self.replacement_suffix:
            raise ValueError("redaction replacement markers must be non-empty")
        if any(not key or "\x00" in key for key in self.additional_sensitive_keys):
            raise ValueError("redaction sensitive keys are invalid")


_SENSITIVE_KEYS = frozenset(
    {
        "access_token",
        "api_key",
        "apikey",
        "auth_token",
        "authorization",
        "client_secret",
        "cookie",
        "credential",
        "credentials",
        "database_password",
        "id_token",
        "passphrase",
        "passwd",
        "password",
        "private_key",
        "proxy_authorization",
        "refresh_token",
        "session_cookie",
        "set_cookie",
        "secret",
        "secret_access_key",
        "token",
    }
)


_TEXT_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "private_key",
        re.compile(
            r"-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----.*?"
            r"-----END(?: [A-Z0-9]+)? PRIVATE KEY-----",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        "cookie",
        re.compile(
            r"(?im)(?P<prefix>^(?:set-cookie|cookie)\s*:\s*)"
            r"(?P<secret>[^\r\n]+)"
        ),
    ),
    (
        "environment_secret",
        re.compile(
            r"(?im)(?P<prefix>^(?:export\s+)?[A-Z_][A-Z0-9_]*"
            r"(?:API_KEY|ACCESS_KEY|AUTH_TOKEN|TOKEN|SECRET|PASSWORD|PASSWD|"
            r"SESSION_COOKIE|COOKIE)\s*=\s*[\"']?)"
            r"(?P<secret>[^\s\"']+)",
        ),
    ),
    (
        "authorization",
        re.compile(
            r"(?im)(?P<prefix>^(?:proxy-)?authorization\s*:\s*(?:basic|bearer)\s+)"
            r"(?P<secret>[^\s,;]+)"
        ),
    ),
    (
        "url_credentials",
        re.compile(
            r"(?P<prefix>\b[a-z][a-z0-9+.-]{1,15}://)"
            r"(?P<secret>[^\s/@:]+:[^\s/@]+)@",
            re.IGNORECASE,
        ),
    ),
    (
        "named_secret",
        re.compile(
            r"(?P<prefix>(?:\b|[\"'])(?:access[_-]?token|api[_-]?key|apikey|"
            r"auth[_-]?token|client[_-]?secret|database[_-]?password|passphrase|"
            r"passwd|password|private[_-]?key|refresh[_-]?token|secret|token)"
            r"(?:[\"'])?\s*(?:=|:)\s*[\"']?)"
            r"(?P<secret>[^\s\"',;&}]+)",
            re.IGNORECASE,
        ),
    ),
    (
        "query_secret",
        re.compile(
            r"(?P<prefix>[?&](?:access[_-]?token|api[_-]?key|apikey|auth[_-]?token|"
            r"client[_-]?secret|password|refresh[_-]?token|secret|token)=)"
            r"(?P<secret>[^&#\s]+)",
            re.IGNORECASE,
        ),
    ),
    (
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    ),
    (
        "openai_token",
        re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}\b"),
    ),
    (
        "github_token",
        re.compile(
            r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})\b"
        ),
    ),
    (
        "slack_token",
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
    ),
    (
        "aws_access_key",
        re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{12}(?:[A-Z0-9]{4})?\b"),
    ),
    (
        "google_api_key",
        re.compile(r"\bAIza[A-Za-z0-9_-]{35}\b"),
    ),
    (
        "stripe_secret_key",
        re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}\b"),
    ),
    (
        "npm_token",
        re.compile(r"\bnpm_[A-Za-z0-9]{30,}\b"),
    ),
    (
        "pypi_token",
        re.compile(r"\bpypi-[A-Za-z0-9_-]{30,}\b"),
    ),
    (
        "bearer_token",
        re.compile(r"(?i)(?P<prefix>\bbearer\s+)(?P<secret>[A-Za-z0-9._~+/-]{20,})"),
    ),
)


def _marker(policy: RedactionPolicy, kind: str) -> str:
    return policy.replacement_prefix + kind + policy.replacement_suffix


def redact_text(value: str, policy: RedactionPolicy | None = None) -> str:
    active = policy or RedactionPolicy()
    if not active.enabled or not value:
        return value
    redacted = value
    for kind, pattern in _TEXT_PATTERNS:
        marker = _marker(active, kind)

        def replace(match: re.Match[str]) -> str:
            groups = match.groupdict()
            prefix = groups.get("prefix")
            if prefix is not None:
                suffix = "@" if kind == "url_credentials" else ""
                return prefix + marker + suffix
            return marker

        redacted = pattern.sub(replace, redacted)
    return redacted


def redact_value(value: Any, policy: RedactionPolicy | None = None) -> Any:
    """Recursively redact JSON-compatible content without mutating the caller."""

    active = policy or RedactionPolicy()
    if not active.enabled:
        return _copy_value(value, active)
    sensitive = _SENSITIVE_KEYS | {
        _normalize_key(key) for key in active.additional_sensitive_keys
    }
    return _redact_value(value, active, sensitive)


def _normalize_key(value: object) -> str:
    key = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", str(value))
    return key.casefold().replace("-", "_")


def _redact_value(value: Any, policy: RedactionPolicy, sensitive: set[str] | frozenset[str]) -> Any:
    if isinstance(value, str):
        return redact_text(value, policy)
    if isinstance(value, Mapping):
        result: dict[Any, Any] = {}
        for key, item in value.items():
            normalized = _normalize_key(key)
            if normalized in sensitive and item not in (None, ""):
                result[key] = _marker(policy, normalized)
            else:
                result[key] = _redact_value(item, policy, sensitive)
        return result
    if isinstance(value, tuple):
        return tuple(_redact_value(item, policy, sensitive) for item in value)
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        return [_redact_value(item, policy, sensitive) for item in value]
    return value


def _copy_value(value: Any, policy: RedactionPolicy) -> Any:
    if isinstance(value, Mapping):
        return {key: _copy_value(item, policy) for key, item in value.items()}
    if isinstance(value, tuple):
        return tuple(_copy_value(item, policy) for item in value)
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_copy_value(item, policy) for item in value]
    return value
