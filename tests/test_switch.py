import asyncio
import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import pytest
from click.testing import CliRunner

from isoforge.cli import main
from isoforge.codec import MAX_MESSAGE_BYTES, build, parse
from isoforge.switch import SwitchError, _bind_hosts, serve

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


@asynccontextmanager
async def _running() -> AsyncIterator[int]:
    server = await serve("127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    async with server:
        yield port


async def _exchange(port: int, payload: bytes) -> bytes:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        writer.write(len(payload).to_bytes(2, "big") + payload)
        await writer.drain()
        header = await asyncio.wait_for(reader.readexactly(2), timeout=2)
        length = int.from_bytes(header, "big")
        return await asyncio.wait_for(reader.readexactly(length), timeout=2)
    finally:
        writer.close()
        await writer.wait_closed()


async def _ping(port: int) -> None:
    reply = parse(await _exchange(port, build(_load("0800.json"))))
    assert reply["t"] == "0810"
    assert reply["39"] == "00"


async def _expect_close(port: int, data: bytes) -> None:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        writer.write(data)
        await writer.drain()
        try:
            incoming = await asyncio.wait_for(reader.read(32), timeout=2)
        except (ConnectionResetError, BrokenPipeError):
            incoming = b""
        assert incoming == b""
    finally:
        writer.close()
        await writer.wait_closed()


def test_switch_refuses_non_loopback() -> None:
    async def check() -> None:
        with pytest.raises(SwitchError):
            await serve("0.0.0.0", 0)
        with pytest.raises(SwitchError):
            await serve("1.2.3.4", 0)
        server = await serve("127.0.0.1", 0)
        try:
            assert server.sockets[0].getsockname()[0] == "127.0.0.1"
        finally:
            server.close()
            await server.wait_closed()

    asyncio.run(check())


def test_bind_hosts_are_loopback_outside_docker() -> None:
    assert _bind_hosts() == ["127.0.0.1"]


def test_switch_help() -> None:
    result = CliRunner().invoke(main, ["switch", "--help"])
    assert result.exit_code == 0
    assert "--port" in result.output


def test_0800_replies_0810() -> None:
    async def check() -> None:
        async with _running() as port:
            reply = parse(await _exchange(port, build(_load("0800.json"))))
            assert reply["t"] == "0810"
            assert reply["39"] == "00"

    asyncio.run(check())


def test_0200_allowed_pan_echoes_trace_and_terminal() -> None:
    async def check() -> None:
        request = _load("0200.json")
        async with _running() as port:
            reply = parse(await _exchange(port, build(request)))
            assert reply["t"] == "0210"
            assert reply["39"] == "00"
            assert reply["11"] == request["11"]
            assert reply["41"] == request["41"]

    asyncio.run(check())


def test_0200_other_pan_is_declined() -> None:
    async def check() -> None:
        request = _load("0200.json")
        request["2"] = "4000000000000002"
        async with _running() as port:
            reply = parse(await _exchange(port, build(request)))
            assert reply["t"] == "0210"
            assert reply["39"] == "14"
            assert reply["11"] == request["11"]
            assert reply["41"] == request["41"]

    asyncio.run(check())


def test_0420_replies_0430() -> None:
    async def check() -> None:
        async with _running() as port:
            reply = parse(await _exchange(port, build(_load("0420.json"))))
            assert reply["t"] == "0430"
            assert reply["39"] == "00"

    asyncio.run(check())


def test_codec_error_with_mti_replies_30() -> None:
    async def check() -> None:
        payload = b"0200" + b"\x80" + b"\x00" * 7
        async with _running() as port:
            reply = parse(await _exchange(port, payload))
            assert reply["t"] == "0210"
            assert reply["39"] == "30"
            await _ping(port)

    asyncio.run(check())


def test_oversized_frame_closes_and_server_answers() -> None:
    async def check() -> None:
        async with _running() as port:
            await _expect_close(port, (MAX_MESSAGE_BYTES + 1).to_bytes(2, "big"))
            await _ping(port)

    asyncio.run(check())


def test_garbage_closes_and_server_answers() -> None:
    async def check() -> None:
        payload = b"zzzzzzzz"
        async with _running() as port:
            await _expect_close(port, len(payload).to_bytes(2, "big") + payload)
            await _ping(port)

    asyncio.run(check())


def test_half_frame_disconnect_and_server_answers() -> None:
    async def check() -> None:
        async with _running() as port:
            _reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(b"\x00")
            await writer.drain()
            writer.close()
            await writer.wait_closed()
            await _ping(port)

    asyncio.run(check())
