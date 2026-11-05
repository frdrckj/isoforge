import asyncio
import ipaddress
from pathlib import Path

from isoforge.codec import MAX_MESSAGE_BYTES, CodecError, build, parse
from isoforge.log import append_run, mask_pan
from isoforge.tlv import TLVError

DEFAULT_TIMEOUT = 5.0


class ClientError(Exception):
    pass


def require_loopback(host: str, *, allow_remote: bool = False) -> str:
    if host == "localhost":
        host = "127.0.0.1"
    if allow_remote:
        return host
    try:
        ip = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ClientError("refusing non-loopback host") from exc
    if not ip.is_loopback:
        raise ClientError("refusing non-loopback host")
    return host


async def transact(host: str, port: int, payload: bytes) -> bytes:
    reader, writer = await asyncio.open_connection(host, port)
    try:
        writer.write(len(payload).to_bytes(2, "big") + payload)
        await writer.drain()
        header = await reader.readexactly(2)
        length = int.from_bytes(header, "big")
        if length > MAX_MESSAGE_BYTES:
            raise ClientError("response exceeds 8192 bytes")
        return await reader.readexactly(length)
    except ClientError:
        raise
    except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError) as exc:
        raise ClientError("connection closed") from exc
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


def send(
    host: str,
    port: int,
    fields: dict,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    log_dir: Path = Path("runs"),
    allow_remote: bool = False,
) -> dict:
    host = require_loopback(host, allow_remote=allow_remote)
    try:
        raw = build(fields)
    except (CodecError, TLVError) as exc:
        raise ClientError(str(exc)) from exc
    try:
        reply_raw = asyncio.run(asyncio.wait_for(transact(host, port, raw), timeout))
    except TimeoutError as exc:
        raise ClientError("timed out") from exc
    except OSError as exc:
        raise ClientError("connection failed") from exc
    try:
        reply = parse(reply_raw)
    except (CodecError, TLVError) as exc:
        raise ClientError(str(exc)) from exc
    pan = fields.get("2")
    secret = pan if isinstance(pan, str) else None
    record = {
        "mti": fields.get("t"),
        "pan": mask_pan(secret) if secret is not None else None,
        "de11": fields.get("11"),
        "de41": fields.get("41"),
        "de39": reply.get("39"),
        "de55": fields.get("55"),
    }
    append_run(log_dir, record, secret)
    return reply
