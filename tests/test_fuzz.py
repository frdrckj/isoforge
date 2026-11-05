import asyncio
import json
from pathlib import Path

from isoforge.codec import build
from isoforge.fuzz import MUTATORS, cases, run_cases
from isoforge.switch import serve

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def _base() -> bytes:
    return build(json.loads((FIXTURES / "0200.json").read_text()))


def test_same_seed_gives_the_same_cases() -> None:
    first = [(item.mutator, item.case_hex) for item in cases(1, 40)]
    second = [(item.mutator, item.case_hex) for item in cases(1, 40)]
    assert first == second
    other = [(item.mutator, item.case_hex) for item in cases(2, 40)]
    assert first != other


def test_each_mutator_changes_the_message() -> None:
    base = _base()
    seen: dict[str, bytes] = {}
    for seed in range(1, 30):
        for case in cases(seed, 8):
            seen.setdefault(case.mutator, case.payload)
        if set(seen) == set(MUTATORS):
            break
    assert set(seen) == set(MUTATORS)
    for payload in seen.values():
        assert payload != base


def test_five_hundred_cases_report_zero_crashes() -> None:
    async def check():
        server = await serve("127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        async with server:
            return await run_cases(1, 500, port, timeout=1)

    summary = asyncio.run(check())
    assert summary.count == 500
    assert summary.crashes == 0
    assert {item.mutator for item in summary.results} == set(MUTATORS)
    assert all(item.case_hex and item.reaction for item in summary.results)
    assert "crashes: 0" in summary.text()
