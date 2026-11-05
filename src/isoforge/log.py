import json
from datetime import UTC, datetime
from pathlib import Path


def mask_pan(pan: str) -> str:
    if len(pan) <= 10:
        return "*" * len(pan)
    return pan[:6] + ("*" * (len(pan) - 10)) + pan[-4:]


def run_path(directory: Path, now: datetime | None = None) -> Path:
    stamp = (now or datetime.now(UTC)).strftime("%Y%m%dT%H%M%SZ")
    return directory / f"{stamp}.jsonl"


def append_run(directory: Path, record: dict, full_pan: str | None) -> Path:
    line = json.dumps(record, separators=(",", ":"))
    if full_pan and full_pan in line:
        raise RuntimeError("refusing to log a full PAN")
    path = run_path(directory)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")
    return path
