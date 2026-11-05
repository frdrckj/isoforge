from iso8583 import DecodeError, EncodeError, decode, encode

from isoforge.spec import SPEC
from isoforge.tlv import TLVError
from isoforge.tlv import build as build_tlv
from isoforge.tlv import parse as parse_tlv

MAX_MESSAGE_BYTES = 8192


class CodecError(Exception):
    def __init__(self, message: str, field: str | None = None) -> None:
        self.field = field
        if field is not None:
            message = f"{message}: field {field}"
        super().__init__(message)


class _TagList(list):
    def __init__(self, items, owner: "ParsedMessage") -> None:
        super().__init__(items)
        self._owner = owner
        self._dead = False

    def _store(self, trial: list) -> None:
        encoded = build_tlv(trial).hex().upper()
        if not self._dead:
            dict.__setitem__(self._owner, "55", encoded)

    def __setitem__(self, index, value) -> None:
        trial = list(self)
        trial[index] = value
        self._store(trial)
        super().__setitem__(index, value)

    def __delitem__(self, index) -> None:
        trial = list(self)
        del trial[index]
        self._store(trial)
        super().__delitem__(index)

    def append(self, value) -> None:
        trial = [*self, value]
        self._store(trial)
        super().append(value)

    def extend(self, values) -> None:
        trial = [*self, *values]
        self._store(trial)
        super().extend(values)

    def insert(self, index, value) -> None:
        trial = list(self)
        trial.insert(index, value)
        self._store(trial)
        super().insert(index, value)

    def pop(self, index=-1):
        trial = list(self)
        item = trial.pop(index)
        self._store(trial)
        super().pop(index)
        return item

    def remove(self, value) -> None:
        trial = list(self)
        trial.remove(value)
        self._store(trial)
        super().remove(value)

    def clear(self) -> None:
        self._store([])
        super().clear()

    def reverse(self) -> None:
        trial = list(reversed(self))
        self._store(trial)
        super().reverse()


class ParsedMessage(dict):
    def __init__(self, fields: dict, de55: list | None) -> None:
        self._tags: _TagList | None = None
        super().__init__(fields)
        if de55 is not None:
            if self._tags is not None:
                self._tags._dead = True
            self._tags = _TagList(de55, self)

    def __setitem__(self, key, value) -> None:
        if key == "55":
            parsed = _parse_de55(value)
            if self._tags is not None:
                self._tags._dead = True
            self._tags = _TagList(parsed, self)
        super().__setitem__(key, value)

    def __delitem__(self, key) -> None:
        if key == "55" and self._tags is not None:
            self._tags._dead = True
            self._tags = None
        super().__delitem__(key)

    def pop(self, key, *args):
        if key == "55" and self._tags is not None:
            self._tags._dead = True
            self._tags = None
        return super().pop(key, *args)

    @property
    def de55(self) -> _TagList | None:
        if "55" not in self:
            return None
        if self._tags is None:
            self._tags = _TagList(parse_tlv(bytes.fromhex(self["55"])), self)
        return self._tags

    @de55.setter
    def de55(self, tags: list | None) -> None:
        if tags is None:
            if self._tags is not None:
                self._tags._dead = True
            self._tags = None
            if "55" in self:
                super().__delitem__("55")
            return
        encoded = build_tlv(list(tags)).hex().upper()
        if self._tags is not None:
            self._tags._dead = True
        dict.__setitem__(self, "55", encoded)
        self._tags = _TagList(list(tags), self)


def _parse_de55(value: object) -> list:
    if not isinstance(value, str):
        raise CodecError("invalid DE55 hex", field="55")
    try:
        return parse_tlv(bytes.fromhex(value))
    except TLVError as exc:
        raise CodecError(str(exc), field="55") from exc
    except ValueError as exc:
        raise CodecError("invalid DE55 hex", field="55") from exc


def build(fields: dict) -> bytes:
    if not isinstance(fields, dict):
        raise CodecError("input must be a dict")
    # pyiso8583 writes the computed bitmap back into the dict it encodes.
    doc = dict(fields)
    try:
        raw, _ = encode(doc, SPEC)
    except EncodeError as exc:
        raise CodecError(exc.msg, field=exc.field) from exc
    except KeyError as exc:
        raise CodecError("field is not defined in the spec", field=str(exc.args[0])) from exc
    except (TypeError, ValueError) as exc:
        # I catch these because pyiso8583 leaks them for a bad value or a numeric-looking key.
        raise CodecError("invalid field value or key") from exc
    return bytes(raw)


def parse(raw: bytes) -> dict:
    if not isinstance(raw, (bytes, bytearray)):
        raise CodecError("input must be bytes or bytearray")
    if len(raw) > MAX_MESSAGE_BYTES:
        raise CodecError(f"input exceeds {MAX_MESSAGE_BYTES} bytes")
    # I only read a primary bitmap. Bit 1 means a secondary bitmap follows,
    # and I reject that before pyiso8583 looks up a field I don't define.
    if len(raw) >= 12 and raw[4] & 0x80:
        raise CodecError("secondary bitmap not supported")
    try:
        decoded, _ = decode(raw, SPEC)
    except DecodeError as exc:
        raise CodecError(exc.msg, field=exc.field) from exc
    except KeyError as exc:
        raise CodecError("field is not defined in the spec", field=str(exc.args[0])) from exc
    # Bitmap is derived from which fields are present.
    decoded.pop("p", None)
    # Field 55 stays the hex string so build() replays the original bytes.
    # de55 is that hex parsed again, and either side updates the other.
    de55: list | None = None
    if "55" in decoded:
        try:
            de55 = parse_tlv(bytes.fromhex(decoded["55"]))
        except TLVError as exc:
            raise CodecError(str(exc), field="55") from exc
        except ValueError as exc:
            raise CodecError("invalid DE55 hex", field="55") from exc
    return ParsedMessage(decoded, de55)
