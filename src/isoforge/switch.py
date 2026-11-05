import asyncio
import fcntl
import ipaddress
import os
import socket
import struct
from collections.abc import Callable

from isoforge.codec import MAX_MESSAGE_BYTES, CodecError, build, parse
from isoforge.tlv import TLVError

# Fixture PANs only. 14 is the ISO response for an invalid card number.
ALLOWED_PANS = frozenset({"4111111111111111", "5555555555554444"})
# 30 is the ISO response for a format error.
FORMAT_ERROR = "30"


class SwitchError(Exception):
    pass


def require_loopback(host: str) -> None:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError as exc:
        raise SwitchError("refusing non-loopback host") from exc
    if not ip.is_loopback:
        raise SwitchError("refusing non-loopback host")


def _reply(fields: dict, mti: str, code: str) -> dict:
    out = {"t": mti, "39": code}
    if "11" in fields:
        out["11"] = fields["11"]
    if "41" in fields:
        out["41"] = fields["41"]
    return out


def _approved(_fields: dict) -> str:
    return "00"


def _authorized(fields: dict) -> str:
    if fields.get("2") in ALLOWED_PANS:
        return "00"
    return "14"


_RULES: dict[str, tuple[str, Callable[[dict], str]]] = {
    "0800": ("0810", _approved),
    "0200": ("0210", _authorized),
    "0420": ("0430", _approved),
}


def readable_mti(payload: bytes) -> str | None:
    if len(payload) < 4 or not payload[:4].isdigit():
        return None
    return payload[:4].decode("ascii")


def response_mti(mti: str) -> str:
    value = int(mti) + 10
    if value > 9999:
        raise CodecError("unreadable mti")
    return f"{value:04d}"


def decide(fields: dict) -> dict:
    mti = fields.get("t")
    rule = _RULES.get(mti) if isinstance(mti, str) else None
    if rule is None:
        raise CodecError("unsupported mti")
    response, code_for = rule
    return _reply(fields, response, code_for(fields))


def handle_payload(payload: bytes) -> bytes | None:
    try:
        reply = decide(parse(payload))
        return build(reply)
    except (CodecError, TLVError):
        mti = readable_mti(payload)
        if mti is None:
            return None
        try:
            return build({"t": response_mti(mti), "39": FORMAT_ERROR})
        except (CodecError, TLVError):
            return None


async def _client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    # One bad client must not take down the accept loop.
    try:
        while True:
            header = await reader.readexactly(2)
            length = int.from_bytes(header, "big")
            if length > MAX_MESSAGE_BYTES:
                break
            payload = await reader.readexactly(length)
            reply = handle_payload(payload)
            if reply is None:
                break
            writer.write(len(reply).to_bytes(2, "big") + reply)
            await writer.drain()
    except Exception:
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def serve(host: str = "127.0.0.1", port: int = 0) -> asyncio.Server:
    require_loopback(host)
    return await asyncio.start_server(_client, host, port)


def _iface_ipv4(name: str) -> str | None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # SIOCGIFADDR. Docker publishes to the container address, not to 0.0.0.0.
        buf = struct.pack("256s", name.encode()[:15])
        out = fcntl.ioctl(sock.fileno(), 0x8915, buf)
    except OSError:
        return None
    finally:
        sock.close()
    return socket.inet_ntoa(out[20:24])


def _bind_hosts() -> list[str]:
    hosts = ["127.0.0.1"]
    if not os.path.exists("/.dockerenv"):
        return hosts
    for name in os.listdir("/sys/class/net"):
        if name == "lo":
            continue
        ip = _iface_ipv4(name)
        if ip and ip not in hosts and ip != "0.0.0.0":
            hosts.append(ip)
    return hosts


async def run(port: int) -> None:
    server = await asyncio.start_server(_client, _bind_hosts(), port)
    async with server:
        await server.serve_forever()
