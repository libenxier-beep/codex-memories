from __future__ import annotations

import hashlib
import json
import math
import os
import platform
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence


class EmbeddingUnavailable(RuntimeError):
    pass


class LocalNaturalLanguageEmbedding:
    """macOS NaturalLanguage sentence embeddings with a local-only JSON seam."""

    MAX_TEXTS = 256
    MAX_TEXT_BYTES = 64 * 1024
    MAX_BATCH_BYTES = 2 * 1024 * 1024

    def __init__(self, *, helper_source: Path, cache_dir: Path) -> None:
        self.helper_source = Path(helper_source).resolve(strict=False)
        self.cache_dir = Path(cache_dir).expanduser().absolute()
        self._description: Optional[Dict[str, Any]] = None

    def _source_digest(self) -> str:
        if platform.system() != "Darwin":
            raise EmbeddingUnavailable("macos_natural_language_unavailable")
        if not self.helper_source.is_file() or self.helper_source.is_symlink():
            raise EmbeddingUnavailable("embedding_helper_source_unavailable")
        try:
            content = self.helper_source.read_bytes()
        except OSError as error:
            raise EmbeddingUnavailable("embedding_helper_source_unreadable") from error
        return hashlib.sha256(content).hexdigest()

    def _binary(self) -> Path:
        digest = self._source_digest()
        self.cache_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        cache_info = self.cache_dir.lstat()
        if (
            self.cache_dir.is_symlink()
            or cache_info.st_uid != os.getuid()
        ):
            raise EmbeddingUnavailable("embedding_cache_not_private")
        os.chmod(self.cache_dir, 0o700)
        cache_info = self.cache_dir.lstat()
        if cache_info.st_mode & 0o077:
            raise EmbeddingUnavailable("embedding_cache_not_private")
        binary = self.cache_dir / ("agent-memory-embedding-" + digest[:24])
        manifest = binary.with_suffix(".sha256")
        if (
            binary.is_file()
            and not binary.is_symlink()
            and os.access(binary, os.X_OK)
            and manifest.is_file()
            and not manifest.is_symlink()
        ):
            expected = manifest.read_text(encoding="ascii").strip()
            actual = hashlib.sha256(binary.read_bytes()).hexdigest()
            if expected == actual and len(expected) == 64:
                return binary
        descriptor, temporary_name = tempfile.mkstemp(prefix=".embedding-helper-", dir=str(self.cache_dir))
        os.close(descriptor)
        temporary = Path(temporary_name)
        manifest_temporary = temporary.with_suffix(".sha256")
        try:
            completed = subprocess.run(
                ["/usr/bin/xcrun", "swiftc", str(self.helper_source), "-O", "-o", str(temporary)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=120,
                env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
            )
            if completed.returncode != 0:
                raise EmbeddingUnavailable(
                    "embedding_helper_compile_failed: {}".format(
                        completed.stderr.decode("utf-8", "replace")[-1000:]
                    )
                )
            os.chmod(temporary, 0o700)
            binary_digest = hashlib.sha256(temporary.read_bytes()).hexdigest()
            manifest_temporary.write_text(binary_digest + "\n", encoding="ascii")
            os.chmod(manifest_temporary, 0o600)
            os.replace(temporary, binary)
            os.replace(manifest_temporary, manifest)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise EmbeddingUnavailable("embedding_helper_compile_unavailable") from error
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
            try:
                manifest_temporary.unlink()
            except FileNotFoundError:
                pass
        return binary

    def _invoke(self, argument: str, *, input_bytes: Optional[bytes] = None) -> Mapping[str, Any]:
        binary = self._binary()
        try:
            completed = subprocess.run(
                [str(binary), argument],
                input=input_bytes,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=60,
                env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise EmbeddingUnavailable("embedding_helper_execution_unavailable") from error
        if completed.returncode != 0:
            raise EmbeddingUnavailable(
                "embedding_helper_failed: {}".format(completed.stderr.decode("utf-8", "replace")[-1000:])
            )
        try:
            value = json.loads(completed.stdout.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise EmbeddingUnavailable("embedding_helper_invalid_output") from error
        if not isinstance(value, dict) or value.get("status") != "ok":
            raise EmbeddingUnavailable("embedding_model_unavailable")
        return value

    def describe(self) -> Mapping[str, Any]:
        if self._description is None:
            value = self._invoke("--describe")
            dimension = value.get("dimension")
            model = value.get("model")
            if not isinstance(dimension, int) or dimension <= 0 or not isinstance(model, str) or not model:
                raise EmbeddingUnavailable("embedding_description_invalid")
            digest = self._source_digest()
            macos_version = platform.mac_ver()[0] or "unknown"
            try:
                build_version = subprocess.run(
                    ["/usr/bin/sw_vers", "-buildVersion"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    check=False,
                    text=True,
                    timeout=5,
                    env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
                ).stdout.strip()
            except (OSError, subprocess.TimeoutExpired):
                build_version = "unknown"
            runtime_version = "macOS-{}-{}".format(macos_version, build_version or "unknown")
            self._description = {
                "status": "ready",
                "provider": "macos_natural_language",
                "model": model,
                "dimension": dimension,
                "fingerprint": hashlib.sha256(
                    (digest + "\0" + model + "\0" + str(dimension) + "\0" + runtime_version).encode("utf-8")
                ).hexdigest(),
                "runtime_version": runtime_version,
                "privacy": "local_only",
                "network": False,
            }
        return dict(self._description)

    def embed(self, texts: Sequence[str]) -> List[List[float]]:
        if not isinstance(texts, Sequence) or isinstance(texts, (str, bytes)):
            raise ValueError("texts must be a sequence")
        if not texts or len(texts) > self.MAX_TEXTS:
            raise ValueError("embedding batch size is invalid")
        encoded_total = 0
        checked: List[str] = []
        for text in texts:
            if not isinstance(text, str) or not text.strip():
                raise ValueError("embedding text is invalid")
            try:
                size = len(text.encode("utf-8"))
            except UnicodeEncodeError as error:
                raise ValueError("embedding text is invalid") from error
            if size > self.MAX_TEXT_BYTES:
                raise ValueError("embedding text exceeds size limit")
            encoded_total += size
            checked.append(text)
        if encoded_total > self.MAX_BATCH_BYTES:
            raise ValueError("embedding batch exceeds size limit")
        payload = json.dumps({"texts": checked}, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        value = self._invoke("--embed", input_bytes=payload)
        vectors = value.get("vectors")
        dimension = self.describe()["dimension"]
        if not isinstance(vectors, list) or len(vectors) != len(checked):
            raise EmbeddingUnavailable("embedding_vectors_invalid")
        result: List[List[float]] = []
        for vector in vectors:
            if not isinstance(vector, list) or len(vector) != dimension:
                raise EmbeddingUnavailable("embedding_vector_dimension_invalid")
            converted = [float(component) for component in vector]
            if not all(math.isfinite(component) for component in converted):
                raise EmbeddingUnavailable("embedding_vector_non_finite")
            norm = math.sqrt(sum(component * component for component in converted))
            if norm <= 0:
                raise EmbeddingUnavailable("embedding_vector_zero_norm")
            result.append([component / norm for component in converted])
        return result
