import json
from pathlib import Path

import pytest

from isoforge.codec import CodecError
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
        "DF810101FF",
        "8200",
    ],
)
def test_length_form_round_trip(hex_value: str) -> None:
    raw = bytes.fromhex(hex_value)
    assert build(parse(raw)) == raw


def test_canonical_long_length_round_trip() -> None:
    raw = bytes.fromhex("9F268180") + (b"\x11" * 128)
    assert build(parse(raw)) == raw


def test_overlong_length_is_rejected() -> None:
    for hex_value in ("9F268108AABBCCDDEEFF0011", "958200050000008000"):
        with pytest.raises(TLVError, match="overlong length") as exc:
            parse(bytes.fromhex(hex_value))
        assert isinstance(exc.value.offset, int)


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


def test_build_rejects_incomplete_multibyte_tag() -> None:
    item = Tag(tag="1F", length=1, value=b"\x00", name="")
    with pytest.raises(TLVError) as exc:
        build([item])
    assert exc.value.offset == 0
    assert "invalid tag" in str(exc.value)


def test_build_rejects_high_bit_last_tag_byte() -> None:
    item = Tag(tag="9F80", length=1, value=b"\x00", name="")
    with pytest.raises(TLVError) as exc:
        build([item])
    assert exc.value.offset == 0
    assert "invalid tag" in str(exc.value)


def test_build_rejects_empty_tag() -> None:
    item = Tag(tag="", length=0, value=b"", name="")
    with pytest.raises(TLVError) as exc:
        build([item])
    assert exc.value.offset == 0
    assert "invalid tag" in str(exc.value)


def test_build_rejects_oversize_output() -> None:
    value = bytes(300)
    item = Tag(tag="82", length=300, value=value, name="")
    with pytest.raises(TLVError) as exc:
        build([item])
    assert exc.value.offset == 0
    assert "output exceeds 255 bytes" in str(exc.value)
    first = Tag(tag="95", length=5, value=b"\x00" * 5, name=lookup("95"))
    second = Tag(tag="82", length=250, value=bytes(250), name=lookup("82"))
    with pytest.raises(TLVError) as exc:
        build([first, second])
    assert exc.value.offset == len(build([first]))
    assert "output exceeds 255 bytes" in str(exc.value)


def test_build_valid_tags_round_trip() -> None:
    items = [
        Tag(tag="95", length=5, value=bytes.fromhex("0000008000"), name=lookup("95")),
        Tag(tag="82", length=2, value=bytes.fromhex("1980"), name=lookup("82")),
        Tag(tag="9F26", length=8, value=bytes.fromhex("AABBCCDDEEFF0011"), name=lookup("9F26")),
        Tag(tag="5F2A", length=2, value=bytes.fromhex("0840"), name=lookup("5F2A")),
        Tag(tag="DF8101", length=1, value=b"\xff", name=lookup("DF8101")),
    ]
    encoded = build(items)
    assert parse(encoded) == items
    assert build(parse(build(items))) == encoded
    exact = Tag(tag="82", length=252, value=bytes(252), name=lookup("82"))
    exact_encoded = build([exact])
    assert len(exact_encoded) == 255
    assert parse(exact_encoded) == [exact]
    assert build(parse(exact_encoded)) == exact_encoded


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


def test_duplicate_tag_is_rejected() -> None:
    with pytest.raises(TLVError, match="duplicate tag") as exc:
        parse(bytes.fromhex("9C01009C0101"))
    assert exc.value.offset == 3
    item = Tag(tag="9C", length=1, value=b"\x00", name=lookup("9C"))
    with pytest.raises(TLVError, match="duplicate tag"):
        build([item, Tag(tag="9C", length=1, value=b"\x01", name=lookup("9C"))])


def test_fixed_width_tags_reject_the_wrong_length() -> None:
    samples = {
        "9F02": "9F020100",
        "9F03": "9F030100",
        "9A": "9A0100",
        "9C": "9C020000",
        "5F2A": "5F2A0100",
        "9F1A": "9F1A0100",
        "95": "950100",
        "9F36": "9F360100",
        "9F37": "9F370100",
    }
    assert set(samples) == {
        "9F02",
        "9F03",
        "9A",
        "9C",
        "5F2A",
        "9F1A",
        "95",
        "9F36",
        "9F37",
    }
    for raw in samples.values():
        with pytest.raises(TLVError, match="invalid length for tag"):
            parse(bytes.fromhex(raw))


def test_padding_between_tlvs_is_skipped() -> None:
    raw = bytes.fromhex("9505000000800000009C0100")
    parsed = parse(raw)
    assert [item.tag for item in parsed] == ["95", "9C"]
    assert parse(b"\x00\x00") == []


def test_de55_stays_in_sync_with_the_tag_list() -> None:
    fields = json.loads((FIXTURES / "0200.json").read_text())
    parsed = parse_message(build_message(fields))
    original = parsed["55"]
    first = parsed.de55[0]
    replacement = Tag(
        tag=first.tag,
        length=first.length,
        value=b"\xab" * first.length,
        name=first.name,
    )
    parsed.de55[0] = replacement
    assert parsed["55"] != original
    assert parse(bytes.fromhex(parsed["55"]))[0].value == replacement.value
    parsed["55"] = original
    assert parsed.de55[0].value == parse(bytes.fromhex(original))[0].value
    parsed.de55 = [replacement]
    assert parse(bytes.fromhex(parsed["55"]))[0].value == replacement.value


def test_codec_error_keeps_the_tlv_offset() -> None:
    fields = json.loads((FIXTURES / "0200.json").read_text())
    fields["55"] = "9F2608AABB"
    with pytest.raises(TLVError) as tlv_exc:
        parse(bytes.fromhex(fields["55"]))
    with pytest.raises(CodecError) as codec_exc:
        parse_message(build_message(fields))
    assert "at offset" in str(codec_exc.value)
    assert str(tlv_exc.value.offset) in str(codec_exc.value)
    assert codec_exc.value.field == "55"


def test_codec_without_de55() -> None:
    fields = json.loads((FIXTURES / "0800.json").read_text())
    parsed = parse_message(build_message(fields))
    assert parsed == fields
    assert parsed.de55 is None
