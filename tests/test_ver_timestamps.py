"""Every instant the Paramify VER reports emit is UTC, second precision, Z.

    2026-07-30T09:00:00Z

The reports mix three timestamp sources — values the fetcher generates, values
passed through from the Paramify API (which returns milliseconds), and report
bounds supplied as config (which may be a bare date). Without normalization one
document carried all three notations. These tests pin the single format.

ver_common lives under fetchers/ and is loaded by path: fetchers are scripts the
runner exec's, not an importable package, so there is no `from fetchers...`
import to make. This mirrors how the runner puts _shared on sys.path.

Run: ``pytest tests/test_ver_timestamps.py``
"""

from __future__ import annotations

import importlib.util
import json
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
_VER_COMMON = REPO_ROOT / "fetchers" / "paramify" / "_shared" / "ver_common.py"

# The one accepted shape. Anchored: a trailing offset or fractional seconds fails.
CANONICAL = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
# Anything date-shaped, so an off-format value is found rather than skipped.
LOOSE = re.compile(r"\d{4}-\d{2}-\d{2}[T ][\d:.]+(?:Z|[+-]\d{2}:\d{2})?")


def _load_ver_common():
    spec = importlib.util.spec_from_file_location("ver_common_under_test", _VER_COMMON)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


vc = _load_ver_common()


@pytest.mark.parametrize("raw,expected", [
    ("2026-02-01T00:00:00.000Z", "2026-02-01T00:00:00Z"),      # API millisecond form
    ("2026-02-01T00:00:00.123456Z", "2026-02-01T00:00:00Z"),   # microseconds
    ("2026-02-01T00:00:00Z", "2026-02-01T00:00:00Z"),          # already canonical
    ("2026-02-01T09:00:00+02:00", "2026-02-01T07:00:00Z"),     # offset -> UTC
    ("2026-02-01T00:00:00-05:00", "2026-02-01T05:00:00Z"),
    ("2026-02-01", "2026-02-01T00:00:00Z"),                    # bare date
    ("2026-02-01T00:00:00", "2026-02-01T00:00:00Z"),           # naive == UTC
])
def test_to_utc_z_normalizes(raw, expected):
    assert vc.to_utc_z(raw) == expected
    assert CANONICAL.match(vc.to_utc_z(raw))


@pytest.mark.parametrize("raw", ["not a date", "", None, "2026-13-45"])
def test_to_utc_z_passes_through_what_it_cannot_parse(raw):
    """Better an off-format value than a silently dropped one — schema
    verification is the right place for a malformed source value to surface."""
    assert vc.to_utc_z(raw) == raw


def test_report_period_bounds_date_only_end_covers_the_whole_day():
    """A date-only end means "through the end of that day" to the coverage
    filter, so reporting its midnight would understate the period by a day."""
    assert vc.report_period_bounds("2026-01-01", "2026-06-30") == (
        "2026-01-01T00:00:00Z", "2026-06-30T23:59:59Z",
    )


def test_report_period_bounds_timestamped_end_is_echoed():
    assert vc.report_period_bounds("2026-01-01", "2026-07-30T15:23:28Z") == (
        "2026-01-01T00:00:00Z", "2026-07-30T15:23:28Z",
    )


def test_report_period_bounds_normalizes_both_ends():
    for bound in vc.report_period_bounds("2026-01-01T00:00:00.000Z", "2026-06-30T12:00:00+02:00"):
        assert CANONICAL.match(bound), bound


def test_current_timestamp_is_canonical():
    assert CANONICAL.match(vc.current_timestamp())


def test_vulnerability_detail_emits_only_canonical_timestamps():
    """The whole mapped object, from an issue whose every date is off-format —
    including the free-text overdue explanation, which interpolates a dueDate."""
    issue = {
        "id": "x", "poamId": "V-1", "status": "OPEN", "level": "HIGH",
        "createdAt": "2026-02-01T00:00:00.000Z",
        "evaluationDate": "2025-01-01T08:30:00.123Z",
        "dueDate": "2020-07-01T00:00:00.000Z",  # long past => overdue, so the
        "description": "messy timestamps",      # explanation is populated
        "deviations": [],
    }
    detail = vc.map_vulnerability_detail(issue)

    assert detail["overdueStatus"]["isOverdue"] is True, "fixture must exercise the explanation"
    # Serialize and scan: catches timestamps in free text (the overdue
    # explanation) as well as in fields, without a bespoke tree walker.
    found = LOOSE.findall(json.dumps(detail))
    assert found, "no timestamps found — the fixture is broken"
    off_format = [ts for ts in found if not CANONICAL.match(ts)]
    assert not off_format, f"off-format timestamps in {json.dumps(detail)}: {off_format}"
