"""Tests for the local FIREMARK trust smoke test."""

from __future__ import annotations

import pytest

from scripts.smoke_trust import main


def test_smoke_trust_reports_success_without_private_material(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main() == 0

    output = capsys.readouterr().out
    assert "PASS" in output
    assert "FAIL" not in output
    assert "not production evidence" in output
    assert "PRIVATE KEY" not in output
    assert "FIREMARK_SIGNING_KEY" not in output
