"""信頼リスト・学習済みアプリ・停止中プロセス・記録の保存。PCの外へは何も送らない。"""
from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path

LOG_LIMIT_BYTES = 5 * 1024 * 1024
SAVE_ATTEMPTS = 10
SAVE_RETRY_SECONDS = 0.05


class Store:
    def __init__(self, data_dir: str | os.PathLike[str]):
        self.dir = Path(data_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._trust: dict[str, dict] = self._load("trust.json", {})
        self._seen: set[str] = set(self._load("seen_apps.json", []))
        self.settings: dict = self._load("settings.json", {})

    def _load(self, name: str, default):
        try:
            return json.loads((self.dir / name).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return default

    def _save(self, name: str, value) -> bool:
        """保存に失敗しても監視や画面は止めない。

        ウイルス対策ソフトなどがファイルを開いている瞬間は置き換えに失敗するので、少し待って再試行する。
        """
        target = self.dir / name
        temp = target.with_suffix(target.suffix + ".tmp")
        detail = ""
        try:
            temp.write_text(json.dumps(value, ensure_ascii=False, indent=1), encoding="utf-8")
            for attempt in range(SAVE_ATTEMPTS):
                try:
                    os.replace(temp, target)
                    return True
                except PermissionError as exc:
                    detail = repr(exc)
                    if attempt + 1 < SAVE_ATTEMPTS:
                        time.sleep(SAVE_RETRY_SECONDS)
        except OSError as exc:
            detail = repr(exc)
        self.log({"event": "save_failed", "file": name, "detail": detail})
        return False

    # --- 信頼リスト（パスとハッシュの両方が一致したときだけ信頼する）
    def is_trusted(self, path: str | None, sha256: str | None) -> bool:
        if not path or not sha256:
            return False
        with self._lock:
            entry = self._trust.get(path.lower())
            return bool(entry and entry.get("sha256") == sha256)

    def has_trust_entry(self, path: str | None) -> bool:
        if not path:
            return False
        with self._lock:
            return path.lower() in self._trust

    def add_trust(self, path: str, sha256: str) -> None:
        with self._lock:
            self._trust[path.lower()] = {
                "path": path,
                "sha256": sha256,
                "added": time.strftime("%Y-%m-%d %H:%M:%S"),
            }
            self._save("trust.json", self._trust)

    def remove_trust(self, path: str) -> None:
        with self._lock:
            if self._trust.pop(path.lower(), None) is not None:
                self._save("trust.json", self._trust)

    def trust_entries(self) -> list[dict]:
        with self._lock:
            return sorted(self._trust.values(), key=lambda e: e.get("path", "").lower())

    # --- これまでに通信を確認したアプリ
    def is_seen(self, path: str | None) -> bool:
        if not path:
            return True
        with self._lock:
            return path.lower() in self._seen

    def mark_seen(self, path: str | None) -> None:
        if not path:
            return
        with self._lock:
            key = path.lower()
            if key not in self._seen:
                self._seen.add(key)
                self._save("seen_apps.json", sorted(self._seen))

    def seen_apps(self) -> list[str]:
        with self._lock:
            return sorted(self._seen)

    # --- 停止中のプロセス（異常終了後に引き継ぐため）
    def load_suspended(self) -> list[dict]:
        with self._lock:
            value = self._load("suspended.json", [])
            return value if isinstance(value, list) else []

    def save_suspended(self, entries: list[dict]) -> None:
        with self._lock:
            self._save("suspended.json", entries)

    # --- 設定
    def save_settings(self) -> None:
        with self._lock:
            self._save("settings.json", self.settings)

    # --- 記録
    def log(self, event: dict) -> None:
        record = {"time": time.strftime("%Y-%m-%d %H:%M:%S"), **event}
        path = self.dir / "events.jsonl"
        with self._lock:
            try:
                if path.exists() and path.stat().st_size > LOG_LIMIT_BYTES:
                    os.replace(path, self.dir / "events.old.jsonl")
                with path.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(record, ensure_ascii=False) + "\n")
            except OSError:
                pass  # 記録の失敗で監視を止めない

    def recent_events(self, limit: int = 200) -> list[dict]:
        path = self.dir / "events.jsonl"
        with self._lock:
            try:
                lines = path.read_text(encoding="utf-8").splitlines()[-limit:]
            except OSError:
                return []
        events = []
        for line in reversed(lines):
            try:
                events.append(json.loads(line))
            except ValueError:
                continue
        return events
