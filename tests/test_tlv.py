import json
from pathlib import Path

import pytest

from isoforge.codec import build as build_message
from isoforge.codec import parse as parse_message
from isoforge.tags import TAG_NAMES, lookup
from isoforge.tlv import Tag, TLVError, build, parse

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"

# Present in fixtures/0200.json. 9F10 and 84 are named, but this DE55 omits them.
PRESENT_NAMES = {
    "9F26": "Application Cryptogram",
    "9F27": "Cryptogram Information Data",
    "9F37": "Unpredictable Number",
    "9F36": "Application Transaction Counter",
    "95": "Terminal Verification Results",
    "9A": "Transaction Date",
    "9C": "Transaction Type",
    "9F02": "Amount Authorised",
    "5F2A": "Transaction Currency Code",
    "82": "Application Interchange Profile",
    "9F1A": "Terminal Country Code",
}


def _de55() -> bytes:
    fields = json.loads((FIXTURES / "0200.json").read_text())
    return bytes.fromhex(fields["55"])


def test_fixture_names_resolve() -> None:
    found = {item.tag: item.name for item in parse(_de55())}
    assert len(TAG_NAMES) == 13
    for tag_id, expected in TAG_NAMES.items():
        assert lookup(tag_id) == expected
        assert expected != "unknown"
    for tag_id, expected in PRESENT_NAMES.items():
        assert found[tag_id] == expected
        assert found[tag_id] != "unknown"


def test_0200_de55_tags_are_named() -> None:
    parsed = parse(_de55())
    assert parsed
    for item in parsed:
        assert item.name != "unknown"


def test_round_trip() -> None:
    raw = _de55()
    assert build(parse(raw)) == raw


@pytest.mark.parametrize(
    "hex_value",
    [
        "9F268108AABBCCDDEEFF0011",
        "958200050000008000",
        "DF810101FF",
        "9500",
    ],
)
def test_length_form_round_trip(hex_value: str) -> None:
    raw = bytes.fromhex(hex_value)
    assert build(parse(raw)) == raw


def test_build_bad_tag_hex() -> None:
    item = Tag(tag="ZZ", length=1, value=b"\x01", name="unknown")
    with pytest.raises(TLVError) as exc:
        build([item])
    assert exc.value.offset == 0


def test_build_none_value() -> None:
    item = Tag(tag="9F02", length=1, value=None, name="unknown")
    with pytest.raises(TLVError) as exc:
        build([item])
    assert exc.value.offset == 0


def test_build_non_list() -> None:
    with pytest.raises(TLVError) as exc:
        build(None)
    assert exc.value.offset == 0


def test_build_mismatched_length_raises() -> None:
    item = Tag(tag="9F02", length=1, value=b"abc", name="Amount Authorised")
    with pytest.raises(TLVError) as exc:
        build([item])
    assert exc.value.offset == 0
    assert "length does not match value" in str(exc.value)


def test_truncated_value() -> None:
    with pytest.raises(TLVError) as exc:
        parse(bytes.fromhex("9F2608AABB"))
    assert isinstance(exc.value.offset, int)


def test_length_past_buffer() -> None:
    with pytest.raises(TLVError) as exc:
        parse(bytes.fromhex("958200FF"))
    assert isinstance(exc.value.offset, int)


def test_indefinite_length() -> None:
    with pytest.raises(TLVError) as exc:
        parse(bytes.fromhex("9580"))
    assert isinstance(exc.value.offset, int)


def test_four_byte_tag() -> None:
    with pytest.raises(TLVError) as exc:
        parse(bytes.fromhex("5F80800100"))
    assert isinstance(exc.value.offset, int)


def test_input_over_255_bytes() -> None:
    with pytest.raises(TLVError) as exc:
        parse(b"\x00" * 256)
    assert isinstance(exc.value.offset, int)


def test_empty_input() -> None:
    assert parse(b"") == []


def test_codec_exposes_parsed_de55() -> None:
    fields = json.loads((FIXTURES / "0200.json").read_text())
    raw = build_message(fields)
    parsed = parse_message(raw)
    assert parsed == fields
    assert parsed["55"] == fields["55"]
    names = {item.tag: item.name for item in parsed.de55}
    for tag_id, expected in PRESENT_NAMES.items():
        assert names[tag_id] == expected
    assert build_message(parsed) == raw


def test_codec_without_de55() -> None:
    fields = json.loads((FIXTURES / "0800.json").read_text())
    parsed = parse_message(build_message(fields))
    assert parsed == fields
    assert parsed.de55 is None
