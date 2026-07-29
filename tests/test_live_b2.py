"""Explicitly gated real Backblaze B2 custody smoke test."""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts.smoke_b2_custody import DEFAULT_ENV_FILE, main


@pytest.mark.live_b2
def test_live_b2_custody(tmp_path: Path) -> None:
    """Run only through the documented dual opt-in and ignored configuration."""
    if not DEFAULT_ENV_FILE.is_file():
        pytest.skip("ignored .env B2 configuration is absent")
    report = tmp_path / "safe-live-report.json"
    assert main(["--live", "--output-report", str(report)]) == 0
