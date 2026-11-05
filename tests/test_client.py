import asyncio
import json
import time
from pathlib import Path

import pytest

from isoforge.client import ClientError, require_loopback, send
from isoforge.switch import serve

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
PAN = "4111111111111111"


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


def test_0200_against_switch_logs_masked_pan(tmp_path: Path) -> None:
    fields = _load("0200.json")

    async def check() -> dict:
        server = await serve("127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        async with server:
            return await asyncio.to_thread(
                send,
                "127.0.0.1",
                port,
                fields,
                timeout=2,
                log_dir=tmp_path,
            )

    reply = asyncio.run(check())
    assert reply["t"] == "0210"
    assert reply["39"] == "00"
    logs = list(tmp_path.glob("*.jsonl"))
    assert len(logs) == 1
    text = logs[0].read_text()
    assert PAN not in text
    assert "411111******1111" in text
    assert fields["55"] in text


def test_non_loopback_host_is_refused(tmp_path: Path) -> None:
    started = time.monotonic()
    with pytest.raises(ClientError, match="refusing non-loopback host"):
        send("10.1.2.3", 8583, {"t": "0800"}, timeout=5, log_dir=tmp_path)
    assert time.monotonic() - started < 0.5
    assert list(tmp_path.glob("*.jsonl")) == []


def test_override_flag_skips_the_loopback_guard() -> None:
    assert require_loopback("10.1.2.3", allow_remote=True) == "10.1.2.3"
    with pytest.raises(ClientError):
        require_loopback("10.1.2.3", allow_remote=False)


def test_timeout_raises_cleanly(tmp_path: Path) -> None:
    async def hang(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while await reader.read(1024):
                pass
        finally:
            writer.close()

    async def check() -> None:
        server = await asyncio.start_server(hang, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        async with server:
            with pytest.raises(ClientError, match="timed out"):
                await asyncio.to_thread(
                    send,
                    "127.0.0.1",
                    port,
                    _load("0800.json"),
                    timeout=0.2,
                    log_dir=tmp_path,
                )

    asyncio.run(check())
    assert list(tmp_path.glob("*.jsonl")) == []
