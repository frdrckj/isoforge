import json
from pathlib import Path

from isoforge.switch import ALLOWED_PANS

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def test_fixture_pans_are_allowed() -> None:
    paths = sorted(FIXTURES.glob("*.json"))
    assert paths
    for path in paths:
        fields = json.loads(path.read_text())
        pan = fields.get("2")
        assert pan is None or pan in ALLOWED_PANS, path.name
