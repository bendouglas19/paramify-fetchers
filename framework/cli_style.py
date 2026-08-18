"""Semantic color for the human CLI.

Colors are the terminal's own 16, not hex, so output follows whatever theme the
reader runs — Catppuccin, Tokyo Night, Solarized, a light theme — instead of
imposing one. The TUI can hardcode Tokyo Night because it paints its own surface;
a CLI writes onto someone else's, so the only honest choice is the palette that
surface already defines. Roles here mirror the TUI's (`framework/tui/palette.py`)
so the two front-ends say pass/warn/fail in the same language: magenta for the
things you name, cyan for the things you set, green/yellow/red for outcomes.

Nothing here decides *whether* to colorize. `typer.echo` strips ANSI when stdout
is not a tty, which is what keeps `--json` machine-readable and CI logs clean;
`NO_COLOR` / `FORCE_COLOR` override that in the CLI's root callback.
"""

from __future__ import annotations

import io

# typer, not click: typer >= 0.26 vendors click as `typer._click` and does NOT depend
# on the standalone `click` distribution, so `import click` only works where something
# else in the environment happens to have pulled it in. It did here, and CI -- which
# installs exactly what pyproject declares -- caught it. typer.style / typer.echo are
# the vendored click functions re-exported, so the behaviour is identical and the
# dependency surface stays at what we actually declare.
import typer

# --------------------------------------------------------------------------- #
# Roles
# --------------------------------------------------------------------------- #

def head(s: str) -> str:
    """A section heading."""
    return typer.style(s, bold=True)


def name(s: str) -> str:
    """An identifier you refer to: a fetcher, category, or manifest."""
    return typer.style(s, fg="magenta")


def env(s: str) -> str:
    """Something you set: an env var name, a config key, a target field."""
    return typer.style(s, fg="cyan")


def path(s: str) -> str:
    """A filesystem path or URL — present, but never the point of the line."""
    return typer.style(s, dim=True)


def dim(s: str) -> str:
    """Secondary detail. `dim` rather than a grey, which only works on one theme."""
    return typer.style(s, dim=True)


def ok(s: str) -> str:
    return typer.style(s, fg="green")


def warn(s: str) -> str:
    return typer.style(s, fg="yellow")


def fail(s: str) -> str:
    return typer.style(s, fg="red")


_MARKS = {
    "OK": lambda s: typer.style(s, fg="green", bold=True),
    "DRY": lambda s: typer.style(s, fg="cyan", bold=True),
    "SKIP": lambda s: typer.style(s, fg="yellow", bold=True),
    "FAIL": lambda s: typer.style(s, fg="red", bold=True),
}


def mark(m: str) -> str:
    """One of the bracketed per-invocation marks the run and upload streams emit."""
    return _MARKS.get(m, head)(m)


def verdict(good: bool, s: str) -> str:
    """A command's closing line — the one thing to see if you see nothing else."""
    return typer.style(s, fg="green" if good else "red", bold=True)


# --------------------------------------------------------------------------- #
# JSON
# --------------------------------------------------------------------------- #
# rich arrives with typer, so it is always installed. Its JSON highlighter is
# used rather than a regex over the text: a `:` or `{` inside a string value is
# exactly the case a regex gets wrong, and evidence payloads are full of prose.
#
# force_terminal puts the codes into the string unconditionally and typer decides
# whether to keep them, so one mechanism governs color for the whole CLI. Width is
# pinned absurdly high with soft_wrap on because this is a highlighter, not a
# layout engine — rich must not re-wrap a payload to the terminal it thinks it has.

def highlight_json(text: str) -> str:
    """Return `text` (already-serialized JSON) with ANSI syntax highlighting."""
    try:
        from rich.console import Console
        from rich.highlighter import JSONHighlighter
    except ImportError:  # pragma: no cover — rich ships with typer
        return text
    buf = io.StringIO()
    Console(
        file=buf, force_terminal=True, soft_wrap=True, width=10_000,
        legacy_windows=False, highlight=False,
    ).print(JSONHighlighter()(text), end="")
    return buf.getvalue()
