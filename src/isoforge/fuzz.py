import asyncio
import json
import random
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from isoforge.client import ClientError, require_loopback, transact
from isoforge.codec import MAX_MESSAGE_BYTES, CodecError, build, parse
from isoforge.spec import SPEC
from isoforge.tlv import TLVError

MUTATORS = ("bitmap_flip", "length_overflow", "field_truncation", "bad_tlv_length")


@dataclass(frozen=True)
class Case:
    mutator: str
    payload: bytes

    @property
    def case_hex(self) -> str:
        return self.payload.hex()


@dataclass(frozen=True)
class Result:
    mutator: str
    case_hex: str
    reaction: str


@dataclass
class Summary:
    count: int
    crashes: int
    results: list[Result] = field(default_factory=list)

    def text(self) -> str:
        by_mutator: dict[str, int] = {name: 0 for name in MUTATORS}
        by_reaction: dict[str, int] = {}
        for item in self.results:
            by_mutator[item.mutator] = by_mutator.get(item.mutator, 0) + 1
            by_reaction[item.reaction] = by_reaction.get(item.reaction, 0) + 1
        lines = [f"cases: {self.count}", f"crashes: {self.crashes}"]
        for name in MUTATORS:
            lines.append(f"{name}: {by_mutator.get(name, 0)}")
        for name in sorted(by_reaction):
            lines.append(f"{name}: {by_reaction[name]}")
        return "\n".join(lines)


def cases(seed: int, count: int) -> list[Case]:
    rng = random.Random(seed)
    base = _base_message()
    names = list(MUTATORS)
    built: list[Case] = []
    for _ in range(count):
        name = rng.choice(names)
        payload = _MUTATE[name](rng, base)
        built.append(Case(name, payload))
    return built


def execute(seed: int, count: int, host: str, port: int, timeout: float = 1.0) -> Summary:
    host = require_loopback(host)
    return asyncio.run(_execute(seed, count, host, port, timeout))


async def run_cases(seed: int, count: int, port: int, timeout: float = 1.0) -> Summary:
    return await _execute(seed, count, "127.0.0.1", port, timeout)


def _base_message() -> bytes:
    for parent in Path(__file__).resolve().parents:
        candidate = parent / "fixtures" / "0200.json"
        if candidate.is_file():
            return build(json.loads(candidate.read_text()))
    cwd = Path("fixtures") / "0200.json"
    if cwd.is_file():
        return build(json.loads(cwd.read_text()))
    raise FileNotFoundError("fixtures/0200.json")


def _bitmap_flip(rng: random.Random, base: bytes) -> bytes:
    buf = bytearray(base)
    bit = rng.randrange(64)
    index = 4 + (bit // 8)
    buf[index] ^= 1 << (7 - (bit % 8))
    return bytes(buf)


def _length_overflow(rng: random.Random, base: bytes) -> bytes:
    spans = [span for span in _field_spans(base) if span[2]]
    span = spans[rng.randrange(len(spans))]
    buf = bytearray(base)
    written = b"9" * span[2]
    if bytes(buf[span[1] : span[1] + span[2]]) == written:
        written = b"8" * span[2]
    buf[span[1] : span[1] + span[2]] = written
    return bytes(buf)


def _field_truncation(rng: random.Random, base: bytes) -> bytes:
    if len(base) < 2:
        return base + b"\xff"
    return base[: rng.randrange(1, len(base))]


def _bad_tlv_length(rng: random.Random, base: bytes) -> bytes:
    spans = {span[0]: span for span in _field_spans(base)}
    _field_no, start, header, data_len = spans["55"]
    body = base[start + header : start + header + data_len]
    offsets = _tlv_length_offsets(body)
    pos = start + header + offsets[rng.randrange(len(offsets))]
    buf = bytearray(base)
    buf[pos] ^= 0x01
    return bytes(buf)


_MUTATE: dict[str, Callable[[random.Random, bytes], bytes]] = {
    "bitmap_flip": _bitmap_flip,
    "length_overflow": _length_overflow,
    "field_truncation": _field_truncation,
    "bad_tlv_length": _bad_tlv_length,
}


def _field_spans(raw: bytes) -> list[tuple[str, int, int, int]]:
    if len(raw) < 12:
        return []
    bitmap = raw[4:12]
    offset = 12
    spans: list[tuple[str, int, int, int]] = []
    for bit in range(2, 65):
        if not _bit_set(bitmap, bit):
            continue
        spec = SPEC.get(str(bit))
        if spec is None or offset >= len(raw):
            break
        header = int(spec["len_type"])
        if offset + header > len(raw):
            break
        if header:
            try:
                data_len = int(raw[offset : offset + header].decode("ascii"))
            except ValueError:
                break
        else:
            data_len = int(spec["max_len"])
        spans.append((str(bit), offset, header, data_len))
        offset += header + data_len
        if offset > len(raw):
            break
    return spans


def _bit_set(bitmap: bytes, field_no: int) -> bool:
    index = field_no - 1
    return bool(bitmap[index // 8] & (1 << (7 - (index % 8))))


def _tlv_length_offsets(data: bytes) -> list[int]:
    offsets: list[int] = []
    index = 0
    while index < len(data):
        if data[index] == 0x00:
            index += 1
            continue
        first = data[index]
        index += 1
        if first & 0x1F == 0x1F:
            while index < len(data) and data[index] & 0x80:
                index += 1
            if index >= len(data):
                break
            index += 1
        if index >= len(data):
            break
        offsets.append(index)
        marker = data[index]
        index += 1
        if marker < 0x80:
            index += marker
            continue
        count = marker & 0x7F
        if index + count > len(data):
            break
        length = int.from_bytes(data[index : index + count], "big")
        index += count + length
    if not offsets:
        raise TLVError("missing tlv length", 0)
    return offsets


async def _execute(seed: int, count: int, host: str, port: int, timeout: float) -> Summary:
    summary = Summary(count=count, crashes=0)
    probe = build(_network_0800())
    for case in cases(seed, count):
        reaction = await _reaction(host, port, case.payload, timeout)
        summary.results.append(Result(case.mutator, case.case_hex, reaction))
        health = await _reaction(host, port, probe, timeout)
        if health != "reply:00":
            summary.crashes += 1
    return summary


def _network_0800() -> dict:
    for parent in Path(__file__).resolve().parents:
        candidate = parent / "fixtures" / "0800.json"
        if candidate.is_file():
            return json.loads(candidate.read_text())
    return json.loads((Path("fixtures") / "0800.json").read_text())


async def _reaction(host: str, port: int, payload: bytes, timeout: float) -> str:
    try:
        raw = await asyncio.wait_for(transact(host, port, payload), timeout)
    except TimeoutError:
        return "timeout"
    except ClientError as exc:
        if str(exc) == "timed out":
            return "timeout"
        return "closed"
    except OSError:
        return "closed"
    if len(raw) > MAX_MESSAGE_BYTES:
        return "closed"
    try:
        reply = parse(raw)
    except (CodecError, TLVError):
        return "closed"
    code = reply.get("39")
    if isinstance(code, str):
        return f"reply:{code}"
    return "reply"
