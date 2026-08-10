import json
from pathlib import Path

import pytest

import marty_verification


FIXTURE_PATH = (
    Path(__file__).resolve().parents[2]
    / "tests"
    / "fixtures"
    / "emrtd_mrz_vectors.json"
)


def _cases():
    fixture = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    assert fixture["schema_version"] == 1
    return fixture["cases"]


@pytest.mark.parametrize("case", _cases(), ids=lambda case: case["id"])
def test_python_binding_matches_shared_mrz_golden_vectors(case):
    if case.get("expect_parse_error", False):
        with pytest.raises(ValueError):
            marty_verification.parse_mrz(case["lines"])
        return

    parsed = marty_verification.parse_mrz(case["lines"])
    expected = case["expected"]
    for field, value in expected.items():
        assert getattr(parsed, field) == value
    assert parsed.check_digits_valid is case["valid_check_digits"]
