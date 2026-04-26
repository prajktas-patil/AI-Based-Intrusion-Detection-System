from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any


def ensure_parent(path: str) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)


def append_jsonl(path: str, payload: dict[str, Any]) -> None:
    ensure_parent(path)
    with Path(path).open("a", encoding="utf-8") as f:
        f.write(json.dumps(payload, default=str) + "\n")


def append_text(path: str, line: str) -> None:
    ensure_parent(path)
    with Path(path).open("a", encoding="utf-8") as f:
        f.write(f"{datetime.utcnow().isoformat()} {line}\n")


def now_iso() -> str:
    return datetime.utcnow().isoformat()
