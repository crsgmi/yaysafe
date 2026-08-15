from __future__ import annotations

import hashlib
import json
import math
import os
import tempfile
import time
from pathlib import Path
from typing import Any

from yaysafe.config import cache_dir
from yaysafe.models import Verdict

CACHE_VERSION = 5
MAX_CACHE_ENTRY_SIZE = 8 * 1024 * 1024
CACHE_MAX_AGE_SECONDS = 7 * 24 * 60 * 60


class ScanCache:
    def __init__(self, root: Path | None = None) -> None:
        self.root = root or cache_dir()

    @staticmethod
    def key(content_digest: str, profile: dict[str, Any]) -> str:
        payload = json.dumps(
            {"digest": content_digest, "profile": profile}, sort_keys=True, separators=(",", ":")
        ).encode()
        return hashlib.sha256(payload).hexdigest()

    def load(self, key: str, content_digest: str) -> Verdict | None:
        if self.root.is_symlink():
            return None
        path = self.root / "scans" / f"{key}.json"
        try:
            if path.is_symlink() or not path.is_file():
                return None
            if path.stat(follow_symlinks=False).st_size > MAX_CACHE_ENTRY_SIZE:
                return None
            data = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                return None
            if data.get("cache_version") != CACHE_VERSION:
                return None
            created_at = data.get("created_at")
            if (
                isinstance(created_at, bool)
                or not isinstance(created_at, (int, float))
                or not math.isfinite(float(created_at))
                or created_at > time.time() + 300
                or time.time() - created_at > CACHE_MAX_AGE_SECONDS
            ):
                return None
            if data.get("content_digest") != content_digest:
                return None
            verdict_data = data.get("verdict")
            if not isinstance(verdict_data, dict):
                return None
            verdict = Verdict.from_dict(verdict_data)
            if verdict.confidence is not None and (
                not math.isfinite(verdict.confidence) or not 0 <= verdict.confidence <= 1
            ):
                return None
            verdict.cached = True
            return verdict
        except (OSError, ValueError, KeyError, TypeError):
            return None

    def store(self, key: str, content_digest: str, verdict: Verdict) -> None:
        directory = self.root / "scans"
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.root.is_symlink() or directory.is_symlink() or not directory.is_dir():
            raise OSError(f"unsafe cache directory: {directory}")
        directory.chmod(0o700)
        payload = json.dumps(
            {
                "cache_version": CACHE_VERSION,
                "created_at": time.time(),
                "content_digest": content_digest,
                "verdict": verdict.to_dict(),
            },
            sort_keys=True,
            indent=2,
        )
        if len(payload.encode("utf-8")) > MAX_CACHE_ENTRY_SIZE:
            return
        fd, raw_path = tempfile.mkstemp(prefix=".scan-", suffix=".tmp", dir=directory)
        temp = Path(raw_path)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            temp.chmod(0o600)
            temp.replace(directory / f"{key}.json")
        finally:
            try:
                temp.unlink(missing_ok=True)
            except OSError:
                pass

    def clear(self) -> int:
        directory = self.root / "scans"
        if self.root.is_symlink() or directory.is_symlink():
            raise OSError(f"unsafe cache directory: {directory}")
        if not directory.exists():
            return 0
        count = 0
        for path in directory.iterdir():
            if path.is_file() and not path.is_symlink():
                path.unlink()
                count += 1
        return count
