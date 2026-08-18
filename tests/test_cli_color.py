"""When the human CLI colorizes, and when it must not.

Color is decided in one place (`cli.py::_root` plus click's own tty detection), so
these pin the three answers that matter rather than any particular styling:

  - piped or redirected: no escapes, because that is where CI logs, `> file` and
    `| grep` live and an escape sequence there is corruption;
  - `--json`: never colored under any setting — it is parsed, not read;
  - FORCE_COLOR / NO_COLOR: the conventions that override the default in each
    direction. FORCE_COLOR is not a nicety: the README demos pipe `paramify
    evidence` into `head`, and without it the payoff frame records in monochrome.
"""

from __future__ import annotations

import json
import re

from typer.testing import CliRunner

from framework.cli import app

runner = CliRunner()

_ANSI = re.compile(r"\x1b\[")


def _run(args, env=None):
    # CliRunner's stdout is never a tty, which is exactly the piped case.
    return runner.invoke(app, args, env=env or {})


def test_piped_output_has_no_escapes() -> None:
    r = _run(["catalog"])
    assert r.exit_code == 0
    assert not _ANSI.search(r.output)


def test_force_color_colorizes_a_pipe() -> None:
    r = _run(["catalog"], env={"FORCE_COLOR": "1"})
    assert r.exit_code == 0
    assert _ANSI.search(r.output)


def test_no_color_wins_over_force_color() -> None:
    """Both set is a real state — a CI job with FORCE_COLOR and a user opting out."""
    r = _run(["catalog"], env={"FORCE_COLOR": "1", "NO_COLOR": "1"})
    assert r.exit_code == 0
    assert not _ANSI.search(r.output)


def test_json_is_never_colored() -> None:
    r = _run(["catalog", "--json"], env={"FORCE_COLOR": "1"})
    assert r.exit_code == 0
    assert not _ANSI.search(r.output)
    json.loads(r.output)  # and still parses


def test_describe_json_is_never_colored() -> None:
    listing = json.loads(_run(["list", "--json"]).output)
    name = listing[0]["name"]
    r = _run(["describe", name, "--json"], env={"FORCE_COLOR": "1"})
    assert r.exit_code == 0
    assert not _ANSI.search(r.output)
    json.loads(r.output)


def test_evidence_json_payload_is_never_colored(tmp_path) -> None:
    """The evidence viewer is the one command that syntax-highlights, so its
    --json path is the one most at risk of shipping escapes to a parser."""
    f = tmp_path / "ev.json"
    f.write_text(json.dumps({"hello": "world"}))
    r = _run(["evidence", str(f), "--json"], env={"FORCE_COLOR": "1"})
    assert r.exit_code == 0
    assert not _ANSI.search(r.output)
    json.loads(r.output)


def test_evidence_human_is_highlighted_under_force_color(tmp_path) -> None:
    f = tmp_path / "ev.json"
    f.write_text(json.dumps({"hello": "world"}))
    r = _run(["evidence", str(f)], env={"FORCE_COLOR": "1"})
    assert r.exit_code == 0
    assert _ANSI.search(r.output)
