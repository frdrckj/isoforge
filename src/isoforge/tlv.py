from dataclasses import dataclass

from isoforge.tags import lookup

MAX_TLV_BYTES = 255
MAX_TAG_BYTES = 3


class TLVError(Exception):
    def __init__(self, message: str, offset: int) -> None:
        self.offset = offset
        super().__init__(f"{message} at offset {offset}")


@dataclass
class Tag:
    tag: str
    length: int
    value: bytes
    name: str


def parse(data: bytes) -> list[Tag]:
    if not isinstance(data, (bytes, bytearray)):
        raise TLVError("input must be bytes", 0)
    # DE55 carries at most 255 bytes. I refuse a longer buffer before the walk.
    if len(data) > MAX_TLV_BYTES:
        raise TLVError("input exceeds 255 bytes", 0)
    data = bytes(data)
    tags: list[Tag] = []
    offset = 0
    try:
        while offset < len(data):
            item, offset = _read_one(data, offset)
            tags.append(item)
    except IndexError as exc:
        # A short buffer raises IndexError on a raw index. Callers only see TLVError.
        raise TLVError("truncated field", offset) from exc
    return tags


def build(tags: list[Tag]) -> bytes:
    out = bytearray()
    for item in tags:
        out += bytes.fromhex(item.tag)
        out += _length_octets(item)
        out += item.value
    return bytes(out)


def _read_one(data: bytes, offset: int) -> tuple[Tag, int]:
    tag_bytes, offset = _read_tag(data, offset)
    length, length_octets, offset = _read_length(data, offset)
    if length > len(data) - offset:
        raise TLVError("length exceeds buffer", offset)
    value = data[offset : offset + length]
    offset += length
    tag_hex = tag_bytes.hex().upper()
    item = Tag(tag=tag_hex, length=length, value=value, name=lookup(tag_hex))
    # Long-form length octets are part of that tag. I keep them when they still match.
    item._length_prefix = length_octets
    return item, offset


def _read_tag(data: bytes, offset: int) -> tuple[bytes, int]:
    first = _at(data, offset, "truncated tag")
    tag = bytearray((first,))
    offset += 1
    if first & 0x1F != 0x1F:
        return bytes(tag), offset
    while True:
        if len(tag) >= MAX_TAG_BYTES:
            raise TLVError("tag exceeds 3 bytes", offset)
        nxt = _at(data, offset, "truncated tag")
        tag.append(nxt)
        offset += 1
        if nxt & 0x80 == 0:
            return bytes(tag), offset


def _read_length(data: bytes, offset: int) -> tuple[int, bytes, int]:
    first = _at(data, offset, "truncated length")
    if first < 0x80:
        return first, bytes((first,)), offset + 1
    if first == 0x80:
        raise TLVError("indefinite length", offset)
    if first not in (0x81, 0x82):
        raise TLVError("unsupported length", offset)
    count = first & 0x7F
    start = offset
    offset += 1
    if offset + count > len(data):
        raise TLVError("truncated length", offset)
    raw = data[start : start + 1 + count]
    length = int.from_bytes(raw[1:], "big")
    return length, raw, start + 1 + count


def _at(data: bytes, offset: int, message: str) -> int:
    if offset < 0 or offset >= len(data):
        raise TLVError(message, offset)
    return data[offset]


def _length_octets(item: Tag) -> bytes:
    prefix = getattr(item, "_length_prefix", b"")
    if isinstance(prefix, bytes) and _prefix_length(prefix) == item.length:
        return prefix
    return _encode_length(item.length)


def _prefix_length(prefix: bytes) -> int | None:
    if len(prefix) == 1 and prefix[0] < 0x80:
        return prefix[0]
    if len(prefix) == 2 and prefix[0] == 0x81:
        return prefix[1]
    if len(prefix) == 3 and prefix[0] == 0x82:
        return int.from_bytes(prefix[1:], "big")
    return None


def _encode_length(length: int) -> bytes:
    if length < 0:
        raise TLVError("negative length", 0)
    if length < 0x80:
        return bytes((length,))
    if length <= 0xFF:
        return bytes((0x81, length))
    if length <= 0xFFFF:
        return bytes((0x82, length >> 8, length & 0xFF))
    raise TLVError("length exceeds 2 bytes", 0)
