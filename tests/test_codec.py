import json
from pathlib import Path

import pytest

from isoforge.codec import CodecError, build, parse

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


@pytest.mark.parametrize("name", ["0800.json", "0200.json", "0420.json"])
def test_round_trip(name: str) -> None:
    fields = json.loads((FIXTURES / name).read_text())
    raw = build(fields)
    assert isinstance(raw, bytes)
    parsed = parse(raw)
    assert parsed == fields
    assert build(parsed) == raw


def test_bad_bitmap() -> None:
    with pytest.raises(CodecError) as exc:
        parse(b"0200" + b"\x80")
    assert exc.value.field == "p"


def test_truncated_message() -> None:
    fields = json.loads((FIXTURES / "0800.json").read_text())
    raw = build(fields)
    with pytest.raises(CodecError) as exc:
        parse(raw[:-1])
    assert exc.value.field == "41"


def test_input_over_8kb() -> None:
    with pytest.raises(CodecError) as exc:
        parse(b"\x00" * 8193)
    assert exc.value.field is None


def test_bad_field_length() -> None:
    with pytest.raises(CodecError) as exc:
        build({"t": "0200", "4": "100"})
    assert exc.value.field == "4"


def test_parse_rejects_non_bytes() -> None:
    with pytest.raises(CodecError):
        parse("0200")
    with pytest.raises(CodecError):
        parse(None)


def test_build_rejects_non_dict() -> None:
    with pytest.raises(CodecError):
        build(None)
    with pytest.raises(CodecError):
        build("x")


def test_build_rejects_none_field_value() -> None:
    with pytest.raises(CodecError):
        build({"t": "0200", "55": None})


def test_build_rejects_int_field_value() -> None:
    with pytest.raises(CodecError):
        build({"t": "0200", "55": 1})


def test_build_rejects_superscript_key() -> None:
    with pytest.raises(CodecError):
        build({"t": "0200", "\u00b2": "1"})


def test_secondary_bitmap_not_supported() -> None:
    # I set bit 1 so parse must refuse a secondary bitmap.
    raw = b"0200" + b"\x80" + b"\x00" * 7
    with pytest.raises(CodecError) as exc:
        parse(raw)
    assert str(exc.value) == "secondary bitmap not supported"
