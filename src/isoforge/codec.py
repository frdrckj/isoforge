from iso8583 import DecodeError, EncodeError, decode, encode

from isoforge.spec import SPEC

MAX_MESSAGE_BYTES = 8192


class CodecError(Exception):
    def __init__(self, message: str, field: str | None = None) -> None:
        self.field = field
        if field is not None:
            message = f"{message}: field {field}"
        super().__init__(message)


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
    return decoded
