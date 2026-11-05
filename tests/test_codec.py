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
