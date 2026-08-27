from __future__ import annotations

import contextlib
import errno
import fcntl
import os
import selectors
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unicodedata
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Iterator, List, Mapping, Optional, Sequence, Tuple

from .model import ControlPlaneError, ValidatorSpec, digest_object, sha256_bytes
from .storage import atomic_write_at, parse_artifact_at, render_artifact


def _trusted_git_executable() -> str:
    for candidate in ("/usr/bin/git", "/bin/git"):
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    resolved = shutil.which("git", path=os.defpath)
    if resolved is None or not os.path.isabs(resolved):
        raise ValueError("a trusted absolute git executable is required")
    return os.path.realpath(resolved)


def _governed_git_environment() -> Dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": os.devnull,
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_COUNT": "0",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "LANG": "C",
        "LC_ALL": "C",
    }


def _read_git_pointer(path: Path, *, prefix: str) -> str:
    try:
        info = path.lstat()
    except FileNotFoundError as error:
        raise ValueError("repository Git binding is missing") from error
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_size > 4096:
        raise ValueError("repository Git binding must be a bounded regular file")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(str(path), flags)
    try:
        raw = os.read(descriptor, 4097)
    finally:
        os.close(descriptor)
    try:
        value = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("repository Git binding is not UTF-8") from error
    if len(raw) > 4096 or "\x00" in value or not value.endswith("\n"):
        raise ValueError("repository Git binding is invalid")
    value = value.strip()
    if prefix:
        marker = prefix + ":"
        if not value.startswith(marker):
            raise ValueError("repository Git binding is invalid")
        value = value[len(marker):].strip()
    if not value or "\n" in value or "\r" in value:
        raise ValueError("repository Git binding is invalid")
    return value


def _repository_git_binding(repository: Path) -> Tuple[Path, Path, Path]:
    """Resolve the repository, per-worktree Git dir, and common Git dir.

    The filesystem's own ``.git`` marker is the authority.  Git process
    environment is compared with this binding by consumers rather than being
    allowed to select a different repository through inherited variables.
    """

    root = Path(os.path.abspath(str(repository))).resolve(strict=True)
    marker = root / ".git"
    try:
        marker_info = marker.lstat()
    except FileNotFoundError as error:
        raise ValueError("repository Git binding is missing") from error
    if stat.S_ISLNK(marker_info.st_mode):
        raise ValueError("repository Git binding cannot be a symlink")
    if stat.S_ISDIR(marker_info.st_mode):
        git_dir = marker.resolve(strict=True)
    elif stat.S_ISREG(marker_info.st_mode):
        pointer = Path(_read_git_pointer(marker, prefix="gitdir"))
        unresolved = pointer if pointer.is_absolute() else root / pointer
        if stat.S_ISLNK(unresolved.lstat().st_mode):
            raise ValueError("repository Git binding cannot target a symlink")
        git_dir = unresolved.resolve(strict=True)
    else:
        raise ValueError("repository Git binding is invalid")
    if not git_dir.is_dir():
        raise ValueError("repository Git binding is not a directory")

    common_marker = git_dir / "commondir"
    if common_marker.exists():
        pointer = Path(_read_git_pointer(common_marker, prefix=""))
        unresolved = pointer if pointer.is_absolute() else git_dir / pointer
        if stat.S_ISLNK(unresolved.lstat().st_mode):
            raise ValueError("repository Git common-dir binding cannot target a symlink")
        common_dir = unresolved.resolve(strict=True)
    else:
        common_dir = git_dir
    if not common_dir.is_dir():
        raise ValueError("repository Git common-dir binding is not a directory")
    return root, git_dir, common_dir


class RepositoryAdapter:
    def __init__(self, repository: Path, control_root: Path) -> None:
        supplied_repository = Path(os.path.abspath(str(repository)))
        self.root = supplied_repository.resolve(strict=True)
        supplied_control_root = Path(control_root)
        if not supplied_control_root.is_absolute():
            supplied_control_root = supplied_repository / supplied_control_root
        supplied_control_root = Path(os.path.abspath(str(supplied_control_root)))
        try:
            control_relative = supplied_control_root.relative_to(supplied_repository)
        except ValueError:
            self.control_root = supplied_control_root
        else:
            self.control_root = self.root / control_relative
        self._assert_control_root_safe(initial=True)
        self._thread_writer_lock = threading.Lock()
        self.git_executable = _trusted_git_executable()
        self.git_environment = _governed_git_environment()
        self._run_git("rev-parse", "--is-inside-work-tree")

    def _assert_control_root_safe(self, *, initial: bool = False) -> None:
        try:
            relative = self.control_root.relative_to(self.root)
        except ValueError as error:
            if initial:
                raise ValueError("control_root must be inside repository") from error
            raise ControlPlaneError("control_root_unsafe", "control_root escaped the repository") from error
        unsafe = self.control_root == self.root or not relative.parts
        current = self.root
        for part in relative.parts:
            current = current / part
            try:
                info = current.lstat()
            except FileNotFoundError:
                break
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                unsafe = True
                break
        try:
            self.control_root.resolve(strict=False).relative_to(self.root)
        except ValueError:
            unsafe = True
        if unsafe:
            message = "control_root must be a non-symlink child directory"
            if initial:
                raise ValueError(message)
            raise ControlPlaneError("control_root_unsafe", message)

    def assert_control_root_safe(self) -> None:
        self._assert_control_root_safe(initial=False)

    @contextlib.contextmanager
    def _open_control_root(self, *, create: bool) -> Iterator[int]:
        relative = self.control_root.relative_to(self.root)
        directory_flags = os.O_RDONLY
        if hasattr(os, "O_DIRECTORY"):
            directory_flags |= os.O_DIRECTORY
        if hasattr(os, "O_NOFOLLOW"):
            directory_flags |= os.O_NOFOLLOW
        descriptors: List[int] = []
        current = os.open(str(self.root), directory_flags)
        descriptors.append(current)
        try:
            for part in relative.parts:
                if create:
                    try:
                        os.mkdir(part, 0o700, dir_fd=current)
                    except FileExistsError:
                        pass
                try:
                    child = os.open(part, directory_flags, dir_fd=current)
                except FileNotFoundError:
                    if not create:
                        raise
                    raise ControlPlaneError(
                        "control_artifact_root_unsafe",
                        "control artifact directory could not be created",
                    )
                except OSError as error:
                    raise ControlPlaneError(
                        "control_artifact_root_unsafe",
                        "control artifact directory must be a non-symlink directory",
                    ) from error
                descriptors.append(child)
                current = child
            yield current
        finally:
            for descriptor in reversed(descriptors):
                os.close(descriptor)

    @contextlib.contextmanager
    def _control_directory(self, subdirectory: str, *, create: bool) -> Iterator[int]:
        if subdirectory not in {"candidates", "approvals", "intents", "receipts"}:
            raise ControlPlaneError(
                "control_artifact_root_unsafe",
                "control artifact directory is not allowlisted",
            )
        directory_flags = os.O_RDONLY
        if hasattr(os, "O_DIRECTORY"):
            directory_flags |= os.O_DIRECTORY
        if hasattr(os, "O_NOFOLLOW"):
            directory_flags |= os.O_NOFOLLOW
        with self._open_control_root(create=create) as control_fd:
            if create:
                try:
                    os.mkdir(subdirectory, 0o700, dir_fd=control_fd)
                except FileExistsError:
                    pass
            try:
                directory_fd = os.open(subdirectory, directory_flags, dir_fd=control_fd)
            except FileNotFoundError:
                raise
            except OSError as error:
                raise ControlPlaneError(
                    "control_artifact_root_unsafe",
                    "control artifact directory must be a non-symlink directory",
                ) from error
            try:
                yield directory_fd
            finally:
                os.close(directory_fd)

    def assert_control_artifact_directory_safe(self, subdirectory: str) -> None:
        path = self.control_root / subdirectory
        try:
            info = path.lstat()
        except FileNotFoundError:
            return
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise ControlPlaneError(
                "control_artifact_root_unsafe",
                "control artifact directory must be a non-symlink directory",
            )

    def control_artifact_exists(self, subdirectory: str, filename: str) -> bool:
        try:
            with self._control_directory(subdirectory, create=False) as directory_fd:
                try:
                    info = os.stat(filename, dir_fd=directory_fd, follow_symlinks=False)
                except FileNotFoundError:
                    return False
                if not stat.S_ISREG(info.st_mode):
                    raise ControlPlaneError(
                        "control_artifact_root_unsafe",
                        "control artifact destination is not a regular file",
                    )
                return True
        except ControlPlaneError:
            raise
        except FileNotFoundError:
            return False

    def read_control_artifact(
        self,
        subdirectory: str,
        filename: str,
        expected_kind: str,
    ) -> Dict[str, Any]:
        with self._control_directory(subdirectory, create=False) as directory_fd:
            return parse_artifact_at(directory_fd, filename, expected_kind)

    def write_control_artifact(
        self,
        subdirectory: str,
        filename: str,
        kind: str,
        value: Mapping[str, Any],
    ) -> None:
        with self._control_directory(subdirectory, create=True) as directory_fd:
            atomic_write_at(directory_fd, filename, render_artifact(kind, value))

    def list_control_artifacts(self, subdirectory: str, prefix: str) -> List[str]:
        try:
            with self._control_directory(subdirectory, create=False) as directory_fd:
                return sorted(
                    name
                    for name in os.listdir(directory_fd)
                    if name.startswith(prefix) and name.endswith(".md")
                )
        except FileNotFoundError:
            return []

    def _run_git_at(
        self,
        root: Path,
        *args: str,
        input_bytes: Optional[bytes] = None,
        error_code: str = "repository_error",
    ) -> bytes:
        completed = subprocess.run(
            [self.git_executable, *args],
            cwd=root,
            env=self.git_environment,
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if completed.returncode != 0:
            message = completed.stderr.decode("utf-8", "replace")[-2000:]
            raise ControlPlaneError(error_code, "git {} failed: {}".format(args[0], message))
        return completed.stdout

    def _run_git(self, *args: str, input_bytes: Optional[bytes] = None) -> bytes:
        return self._run_git_at(self.root, *args, input_bytes=input_bytes)

    def base_revision(self) -> str:
        return self._run_git("rev-parse", "HEAD").decode("ascii").strip()

    def branch(self) -> str:
        completed = subprocess.run(
            [self.git_executable, "symbolic-ref", "--quiet", "--short", "HEAD"],
            cwd=self.root,
            env=self.git_environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if completed.returncode == 0:
            return completed.stdout.decode("utf-8").strip()
        return "(detached)"

    def worktree_identity(self) -> str:
        common = self._run_git("rev-parse", "--git-common-dir").decode("utf-8").strip()
        common_path = Path(common)
        if not common_path.is_absolute():
            common_path = (self.root / common_path).resolve()
        return digest_object(
            {
                "repository_root": str(self.root),
                "git_common_dir": str(common_path),
            }
        )

    def tracked_workspace_records(self) -> List[Dict[str, Any]]:
        index_rows = self._run_git("ls-files", "-s", "-z").split(b"\0")
        records: List[Dict[str, Any]] = []
        control_relative = self.control_root.relative_to(self.root).as_posix()
        for row in index_rows:
            if not row:
                continue
            metadata, encoded_path = row.split(b"\t", 1)
            relative = encoded_path.decode("utf-8", "surrogateescape")
            if relative == control_relative or relative.startswith(control_relative + "/"):
                continue
            path = self.root / PurePosixPath(relative)
            record: Dict[str, Any] = {
                "index": metadata.decode("ascii"),
                "path": relative,
            }
            try:
                info = path.lstat()
            except FileNotFoundError:
                record["worktree"] = "missing"
            else:
                if stat.S_ISLNK(info.st_mode):
                    record["worktree"] = "symlink"
                    record["target"] = os.readlink(str(path))
                elif stat.S_ISREG(info.st_mode):
                    record["worktree"] = sha256_bytes(path.read_bytes())
                    record["mode"] = stat.S_IMODE(info.st_mode)
                else:
                    record["worktree"] = "non_regular"
            records.append(record)
        return records

    def tracked_workspace_digest(self) -> str:
        return digest_object(self.tracked_workspace_records())

    def _untracked_authority_record(self, relative: str) -> Dict[str, Any]:
        path = self.root / PurePosixPath(relative)
        record: Dict[str, Any] = {"path": relative, "untracked": True}
        try:
            info = path.lstat()
        except FileNotFoundError:
            record["worktree"] = "missing"
        else:
            if stat.S_ISLNK(info.st_mode):
                record["worktree"] = "symlink"
                record["target"] = os.readlink(str(path))
            elif stat.S_ISREG(info.st_mode):
                record["worktree"] = sha256_bytes(path.read_bytes())
                record["mode"] = stat.S_IMODE(info.st_mode)
            else:
                record["worktree"] = "non_regular"
        return record

    def complete_workspace_digest(
        self,
        allowed_subtrees: Sequence[str],
        *,
        allowed_untracked_authority: Sequence[str] = (),
    ) -> str:
        actual_untracked = set(self.untracked_authority_paths(allowed_subtrees))
        allowed = set(allowed_untracked_authority)
        unexpected = actual_untracked - allowed
        missing = allowed - actual_untracked
        if unexpected or missing:
            raise ControlPlaneError(
                "unpublished_authority_state",
                "unpublished authority differs from the bound post-state",
            )
        untracked_records = [
            self._untracked_authority_record(relative)
            for relative in sorted(actual_untracked)
        ]
        return digest_object(
            {
                "tracked": self.tracked_workspace_records(),
                "untracked_authority": untracked_records,
            }
        )

    def expected_post_workspace_digest(
        self,
        allowed_subtrees: Sequence[str],
        *,
        relative: str,
        after_bytes: bytes,
        mode: int,
        operation: str,
    ) -> str:
        if self.untracked_authority_paths(allowed_subtrees):
            raise ControlPlaneError(
                "unpublished_authority_state",
                "unpublished authority exists in an allowed subtree",
            )
        records = self.tracked_workspace_records()
        found = False
        for record in records:
            if record.get("path") != relative:
                continue
            found = True
            record.pop("target", None)
            record["worktree"] = sha256_bytes(after_bytes)
            record["mode"] = mode
        untracked_records: List[Dict[str, Any]] = []
        if operation in {"add", "tombstone"}:
            if found:
                raise ControlPlaneError("target_precondition_stale", "add target became tracked")
            untracked_records.append(
                {
                    "path": relative,
                    "untracked": True,
                    "worktree": sha256_bytes(after_bytes),
                    "mode": mode,
                }
            )
        elif operation == "update" and not found:
            raise ControlPlaneError("target_precondition_stale", "update target is no longer tracked")
        return digest_object(
            {
                "tracked": records,
                "untracked_authority": untracked_records,
            }
        )

    def untracked_authority_paths(self, allowed_subtrees: Sequence[str]) -> List[str]:
        ordinary = self._run_git(
            "ls-files",
            "--others",
            "--exclude-standard",
            "-z",
            "--",
            *sorted(set(allowed_subtrees)),
        ).split(b"\0")
        ignored = self._run_git(
            "ls-files",
            "--others",
            "--ignored",
            "--exclude-standard",
            "-z",
            "--",
            *sorted(set(allowed_subtrees)),
        ).split(b"\0")
        return sorted(
            row.decode("utf-8", "surrogateescape")
            for row in set(ordinary + ignored)
            if row
        )

    def unsafe_index_paths(self, paths: Optional[Sequence[str]] = None) -> List[str]:
        arguments: Tuple[str, ...] = ()
        if paths:
            arguments = ("--", *sorted(set(paths)))
        rows = self._run_git("ls-files", "-v", "-z", *arguments).split(b"\0")
        unsafe = []
        for row in rows:
            if not row or len(row) < 3 or row[1:2] != b" ":
                continue
            tag = chr(row[0])
            if tag == "S" or tag.islower():
                unsafe.append(row[2:].decode("utf-8", "surrogateescape"))
        unmerged = self._run_git("ls-files", "-u", "-z", *arguments).split(b"\0")
        for row in unmerged:
            if not row:
                continue
            _metadata, encoded_path = row.split(b"\t", 1)
            unsafe.append(encoded_path.decode("utf-8", "surrogateescape"))
        return sorted(set(unsafe))

    def assert_publishable_authority_state(self, allowed_subtrees: Sequence[str]) -> None:
        if self.untracked_authority_paths(allowed_subtrees):
            raise ControlPlaneError(
                "unpublished_authority_state",
                "unpublished authority exists in an allowed subtree",
            )
        if self.unsafe_index_paths():
            raise ControlPlaneError(
                "workspace_index_unsafe",
                "repository index state uses hidden or unmerged entries",
            )

    def gitlinks(self) -> List[Tuple[str, str]]:
        rows = self._run_git("ls-tree", "-r", "-z", "--full-tree", "HEAD").split(b"\0")
        links: List[Tuple[str, str]] = []
        for row in rows:
            if not row:
                continue
            metadata, encoded_path = row.split(b"\t", 1)
            mode, object_type, object_id = metadata.decode("ascii").split()
            if mode == "160000" and object_type == "commit":
                links.append((encoded_path.decode("utf-8", "surrogateescape"), object_id))
        return links

    def _path_components_safe(self, relative: str) -> Optional[str]:
        current = self.root
        parts = PurePosixPath(relative).parts
        for index, part in enumerate(parts):
            if current.exists() and current.is_dir():
                folded = unicodedata.normalize("NFC", part).casefold()
                for sibling in current.iterdir():
                    if unicodedata.normalize("NFC", sibling.name).casefold() == folded and sibling.name != part:
                        return "path_collision"
            current = current / part
            try:
                info = current.lstat()
            except FileNotFoundError:
                continue
            if stat.S_ISLNK(info.st_mode):
                return "symlink_escape"
            if index < len(parts) - 1 and not stat.S_ISDIR(info.st_mode):
                return "path_invalid"
        try:
            current.resolve(strict=False).relative_to(self.root)
        except ValueError:
            return "path_invalid"
        return None

    @contextlib.contextmanager
    def _open_authority_parent(
        self,
        relative: str,
        *,
        create: bool,
    ) -> Iterator[Tuple[int, str]]:
        parts = PurePosixPath(relative).parts
        if not parts or any(part in {"", ".", ".."} for part in parts):
            raise ControlPlaneError("path_invalid", "destination path is invalid")
        directory_flags = os.O_RDONLY
        if hasattr(os, "O_DIRECTORY"):
            directory_flags |= os.O_DIRECTORY
        if hasattr(os, "O_NOFOLLOW"):
            directory_flags |= os.O_NOFOLLOW
        descriptors: List[int] = []
        try:
            current = os.open(str(self.root), directory_flags)
            descriptors.append(current)
            for part in parts[:-1]:
                folded = unicodedata.normalize("NFC", part).casefold()
                if any(
                    unicodedata.normalize("NFC", sibling).casefold() == folded
                    and sibling != part
                    for sibling in os.listdir(current)
                ):
                    raise ControlPlaneError("path_collision", "destination path collides by case")
                if create:
                    try:
                        os.mkdir(part, 0o755, dir_fd=current)
                    except FileExistsError:
                        pass
                try:
                    child = os.open(part, directory_flags, dir_fd=current)
                except FileNotFoundError as error:
                    raise ControlPlaneError("path_invalid", "destination parent is missing") from error
                except OSError as error:
                    code = "symlink_escape" if error.errno == errno.ELOOP else "path_invalid"
                    raise ControlPlaneError(code, "destination parent is unsafe") from error
                descriptors.append(child)
                current = child
            name = parts[-1]
            folded = unicodedata.normalize("NFC", name).casefold()
            if any(
                unicodedata.normalize("NFC", sibling).casefold() == folded
                and sibling != name
                for sibling in os.listdir(current)
            ):
                raise ControlPlaneError("path_collision", "destination path collides by case")
            yield current, name
        finally:
            for descriptor in reversed(descriptors):
                os.close(descriptor)

    def _target_precondition_at(
        self,
        parent_fd: int,
        name: str,
        operation: str,
    ) -> Tuple[Optional[Dict[str, Any]], List[str]]:
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(name, flags, dir_fd=parent_fd)
        except FileNotFoundError:
            if operation == "update":
                return None, ["target_missing"]
            return {"state": "absent"}, []
        except OSError as error:
            code = "symlink_escape" if error.errno == errno.ELOOP else "path_invalid"
            return None, [code]
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                return None, ["path_invalid"]
            if operation in {"add", "tombstone"}:
                return None, ["target_exists"]
            with os.fdopen(os.dup(descriptor), "rb") as handle:
                content = handle.read()
            return {
                "state": "present",
                "sha256": sha256_bytes(content),
                "mode": stat.S_IMODE(info.st_mode),
                "size": info.st_size,
            }, []
        finally:
            os.close(descriptor)

    @staticmethod
    def _allocate_temp_at(directory_fd: int, mode: int) -> Tuple[int, str]:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        for _attempt in range(32):
            name = ".memory-write-" + secrets.token_hex(16)
            try:
                return os.open(name, flags, mode, dir_fd=directory_fd), name
            except FileExistsError:
                continue
        raise ControlPlaneError("control_artifact_root_unsafe", "cannot allocate authority temp file")

    def target_precondition(self, relative: str, operation: str) -> Tuple[Optional[Dict[str, Any]], List[str]]:
        unsafe = self._path_components_safe(relative)
        if unsafe is not None:
            return None, [unsafe]
        path = self.root / PurePosixPath(relative)
        try:
            info = path.lstat()
        except FileNotFoundError:
            if operation == "update":
                return None, ["target_missing"]
            return {"state": "absent"}, []
        if not stat.S_ISREG(info.st_mode):
            return None, ["path_invalid"]
        if operation in {"add", "tombstone"}:
            return None, ["target_exists"]
        return {
            "state": "present",
            "sha256": sha256_bytes(path.read_bytes()),
            "mode": stat.S_IMODE(info.st_mode),
            "size": info.st_size,
        }, []

    @staticmethod
    def precondition_matches(expected: Mapping[str, Any], actual: Mapping[str, Any]) -> bool:
        if expected.get("state") != actual.get("state"):
            return False
        if expected.get("state") == "absent":
            return True
        return (
            expected.get("sha256") == actual.get("sha256")
            and expected.get("mode") == actual.get("mode")
        )

    @contextlib.contextmanager
    def writer_lock(self) -> Iterator[None]:
        flags = os.O_CREAT | os.O_RDWR
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        with self._thread_writer_lock:
            with self._open_control_root(create=True) as control_fd:
                try:
                    descriptor = os.open(".writer.lock", flags, 0o600, dir_fd=control_fd)
                except OSError as error:
                    raise ControlPlaneError(
                        "control_artifact_root_unsafe",
                        "writer lock must be a non-symlink regular file",
                    ) from error
                if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                    os.close(descriptor)
                    raise ControlPlaneError(
                        "control_artifact_root_unsafe",
                        "writer lock must be a regular file",
                    )
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX)
                    yield
                finally:
                    try:
                        fcntl.flock(descriptor, fcntl.LOCK_UN)
                    finally:
                        os.close(descriptor)

    @contextlib.contextmanager
    def prospective_root(self, relative: str, after_bytes: bytes, mode: int) -> Iterator[Path]:
        with tempfile.TemporaryDirectory(prefix="memory-control-prospective-") as temporary:
            prospective = Path(temporary) / "repository"
            completed = subprocess.run(
                [
                    self.git_executable,
                    "clone",
                    "--quiet",
                    "--no-hardlinks",
                    "--no-checkout",
                    str(self.root),
                    str(prospective),
                ],
                env=self.git_environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            if completed.returncode != 0:
                raise ControlPlaneError(
                    "prospective_build_failed",
                    "cannot clone prospective repository: {}".format(
                        completed.stderr.decode("utf-8", "replace")[-2000:]
                    ),
                )
            branch = self.branch()
            base = self.base_revision()
            if branch == "(detached)":
                checkout = [self.git_executable, "checkout", "--quiet", "--detach", base]
            else:
                checkout = [self.git_executable, "checkout", "--quiet", "-B", branch, base]
            completed = subprocess.run(
                checkout,
                cwd=prospective,
                env=self.git_environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            if completed.returncode != 0:
                raise ControlPlaneError(
                    "prospective_build_failed",
                    "cannot checkout prospective base: {}".format(
                        completed.stderr.decode("utf-8", "replace")[-2000:]
                    ),
                )
            gitlinks = self.gitlinks()
            diff_args: List[str] = ["diff", "--no-ext-diff", "--no-textconv", "--binary", "HEAD", "--", "."]
            diff_args.extend(":(exclude){}".format(path) for path, _object_id in gitlinks)
            patch = self._run_git(*diff_args)
            if patch:
                completed = subprocess.run(
                    [self.git_executable, "apply", "--index", "--binary", "-"],
                    cwd=prospective,
                    env=self.git_environment,
                    input=patch,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )
                if completed.returncode != 0:
                    raise ControlPlaneError(
                        "prospective_build_failed",
                        "cannot apply current tracked snapshot: {}".format(
                            completed.stderr.decode("utf-8", "replace")[-2000:]
                        ),
                    )
            for gitlink_path, object_id in gitlinks:
                source = self.root / PurePosixPath(gitlink_path)
                destination = prospective / PurePosixPath(gitlink_path)
                if not source.is_dir():
                    raise ControlPlaneError(
                        "prospective_build_failed",
                        "local source for gitlink {} is unavailable".format(gitlink_path),
                    )
                destination.parent.mkdir(parents=True, exist_ok=True)
                completed = subprocess.run(
                    [
                        self.git_executable,
                        "clone",
                        "--quiet",
                        "--shared",
                        "--no-checkout",
                        str(source),
                        str(destination),
                    ],
                    env=self.git_environment,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )
                if completed.returncode != 0:
                    raise ControlPlaneError(
                        "prospective_build_failed",
                        "cannot clone gitlink {} from local object store: {}".format(
                            gitlink_path,
                            completed.stderr.decode("utf-8", "replace")[-2000:],
                        ),
                    )
                completed = subprocess.run(
                    [self.git_executable, "checkout", "--quiet", "--detach", object_id],
                    cwd=destination,
                    env=self.git_environment,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )
                if completed.returncode != 0:
                    raise ControlPlaneError(
                        "prospective_build_failed",
                        "gitlink {} does not contain pinned object {}".format(gitlink_path, object_id),
                    )
            target = prospective / PurePosixPath(relative)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(after_bytes)
            os.chmod(str(target), mode)
            completed = subprocess.run(
                [self.git_executable, "add", "--", relative],
                cwd=prospective,
                env=self.git_environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            if completed.returncode != 0:
                raise ControlPlaneError("prospective_build_failed", "cannot stage prospective target")
            architecture_validator = prospective / "scripts" / "validate_memory_architecture.py"
            if architecture_validator.is_file():
                agents_path = prospective.parent / "AGENTS.md"
                agents_path.write_text(
                    "# Prospective runtime\n\n"
                    "<!-- BEGIN GENERATED: codex-ring0 -->\n"
                    "placeholder\n"
                    "<!-- END GENERATED: codex-ring0 -->\n",
                    encoding="utf-8",
                )
                completed = subprocess.run(
                    [
                        sys.executable,
                        "scripts/validate_memory_architecture.py",
                        "--write",
                        "--agents-path",
                        str(agents_path),
                        "--format",
                        "json",
                    ],
                    cwd=prospective,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )
                if completed.returncode != 0:
                    raise ControlPlaneError(
                        "prospective_build_failed",
                        "cannot project prospective Ring 0 adapter: {}".format(
                            (completed.stdout + completed.stderr).decode("utf-8", "replace")[-2000:]
                        ),
                    )
            yield prospective

    def run_validators(self, root: Path, validators: Sequence[ValidatorSpec]) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        home = root / ".memory-control-home"
        home.mkdir(exist_ok=True)
        environment = {
            "PATH": "/usr/bin:/bin",
            "HOME": str(home),
            "LANG": "C",
            "LC_ALL": "C",
            "PYTHONIOENCODING": "utf-8",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_COUNT": "0",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_TERMINAL_PROMPT": "0",
        }
        for validator in validators:
            started = time.monotonic()
            process = subprocess.Popen(
                list(validator.argv),
                cwd=root,
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            if process.stdout is None:
                process.kill()
                process.wait()
                raise ControlPlaneError("validation_failed", "validator output pipe is unavailable")
            output_buffer = bytearray()
            failure_reason: Optional[str] = None
            deadline = started + validator.timeout_seconds
            selector = selectors.DefaultSelector()
            selector.register(process.stdout, selectors.EVENT_READ)
            try:
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        failure_reason = "validator_timeout"
                        process.kill()
                        break
                    events = selector.select(min(remaining, 0.1))
                    for key, _mask in events:
                        chunk = os.read(key.fileobj.fileno(), 65536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        remaining_budget = validator.max_output_bytes + 1 - len(output_buffer)
                        if remaining_budget > 0:
                            output_buffer.extend(chunk[:remaining_budget])
                        if len(output_buffer) > validator.max_output_bytes:
                            failure_reason = "output_limit"
                            process.kill()
                            break
                    if failure_reason is not None:
                        break
                    if process.poll() is not None and not events:
                        try:
                            selector.unregister(process.stdout)
                        except KeyError:
                            pass
            finally:
                selector.close()
                process.stdout.close()
            process.wait()
            output = bytes(output_buffer)
            if failure_reason == "validator_timeout":
                result = {
                    "name": validator.name,
                    "passed": False,
                    "exit_code": None,
                    "reason": "validator_timeout",
                    "output_sha256": sha256_bytes(output),
                    "output_bytes": len(output),
                    "argv_digest": digest_object(list(validator.argv)),
                    "duration_ms": int((time.monotonic() - started) * 1000),
                }
                results.append(result)
                raise ControlPlaneError(
                    "validation_failed",
                    "validator {} failed: timeout".format(validator.name),
                )
            too_large = failure_reason == "output_limit"
            passed = process.returncode == 0 and not too_large
            result = {
                "name": validator.name,
                "passed": passed,
                "exit_code": process.returncode,
                "reason": "output_limit" if too_large else ("passed" if passed else "nonzero_exit"),
                "output_sha256": sha256_bytes(output),
                "output_bytes": len(output),
                "argv_digest": digest_object(list(validator.argv)),
                "duration_ms": int((time.monotonic() - started) * 1000),
            }
            results.append(result)
            if not passed:
                bounded = output[: validator.max_output_bytes].decode("utf-8", "replace")
                raise ControlPlaneError(
                    "validation_failed",
                    "validator {} failed: {}".format(validator.name, bounded.strip()),
                )
        return results

    def atomic_apply(
        self,
        relative: str,
        after_bytes: bytes,
        expected: Mapping[str, Any],
        *,
        failpoint: Optional[str] = None,
    ) -> Dict[str, Any]:
        actual, reasons = self.target_precondition(relative, "update" if expected.get("state") == "present" else "add")
        if reasons or actual is None or not self.precondition_matches(expected, actual):
            raise ControlPlaneError("target_precondition_stale", "target precondition is stale")
        prior_mode = int(expected.get("mode", 0o644))
        self.assert_control_root_safe()
        operation = "update" if expected.get("state") == "present" else "add"
        with self._open_authority_parent(relative, create=True) as (parent_fd, target_name):
            latest, latest_reasons = self._target_precondition_at(parent_fd, target_name, operation)
            if latest_reasons or latest is None or not self.precondition_matches(expected, latest):
                raise ControlPlaneError("target_precondition_stale", "target precondition is stale")
            prior_uid: Optional[int] = None
            prior_gid: Optional[int] = None
            if latest.get("state") == "present":
                info = os.stat(target_name, dir_fd=parent_fd, follow_symlinks=False)
                prior_uid, prior_gid = info.st_uid, info.st_gid
            with self._open_control_root(create=True) as control_fd:
                descriptor, temporary_name = self._allocate_temp_at(control_fd, prior_mode)
                try:
                    os.fchmod(descriptor, prior_mode)
                    if prior_uid is not None and hasattr(os, "fchown"):
                        try:
                            os.fchown(descriptor, prior_uid, prior_gid if prior_gid is not None else -1)
                        except PermissionError:
                            pass
                    with os.fdopen(descriptor, "wb", closefd=True) as handle:
                        descriptor = -1
                        handle.write(after_bytes)
                        handle.flush()
                        os.fsync(handle.fileno())
                    if failpoint == "crash_after_temp_fsync":
                        os._exit(92)
                    latest, latest_reasons = self._target_precondition_at(
                        parent_fd,
                        target_name,
                        operation,
                    )
                    if latest_reasons or latest is None or not self.precondition_matches(expected, latest):
                        raise ControlPlaneError("target_precondition_stale", "target precondition is stale")
                    os.replace(
                        temporary_name,
                        target_name,
                        src_dir_fd=control_fd,
                        dst_dir_fd=parent_fd,
                    )
                    temporary_name = ""
                    os.fsync(parent_fd)
                except BaseException:
                    if descriptor >= 0:
                        os.close(descriptor)
                    if temporary_name:
                        try:
                            os.unlink(temporary_name, dir_fd=control_fd)
                        except FileNotFoundError:
                            pass
                    raise
            after, after_reasons = self._target_precondition_at(parent_fd, target_name, "update")
        if after_reasons or after is None:
            raise ControlPlaneError("receipt_invalid", "workspace after state is unavailable")
        if after["sha256"] != sha256_bytes(after_bytes):
            raise ControlPlaneError("receipt_invalid", "workspace after digest does not match expected bytes")
        return after
