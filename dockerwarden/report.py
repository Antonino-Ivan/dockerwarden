"""Resa dei risultati: testo, JSON e annotazioni GitHub."""

from __future__ import annotations

import json
import os
import sys

from .rules import ERROR, NOTE, WARNING, Finding

_ANSI = {
    ERROR: "\033[31m",
    WARNING: "\033[33m",
    NOTE: "\033[36m",
    "dim": "\033[2m",
    "bold": "\033[1m",
    "reset": "\033[0m",
}

_LABEL = {ERROR: "errore ", WARNING: "avviso ", NOTE: "nota   "}


def use_color(stream=sys.stdout) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return hasattr(stream, "isatty") and stream.isatty()


def _paint(text: str, style: str, enabled: bool) -> str:
    return f"{_ANSI[style]}{text}{_ANSI['reset']}" if enabled else text


def render_text(findings: list[Finding], path: str, *, explain: bool = False, stream=sys.stdout) -> str:
    color = use_color(stream)
    if not findings:
        return _paint(f"OK  {path}: nessun problema rilevato", "bold", color)

    lines: list[str] = []
    for finding in findings:
        label = _paint(_LABEL[finding.severity], finding.severity, color)
        location = _paint(f"{path}:{finding.line}", "dim", color)
        lines.append(f"{label} {finding.code}  {finding.title}")
        lines.append(f"        {finding.message}")
        lines.append(f"        {location}")
        if explain and finding.help_text:
            lines.append(f"        {_paint(finding.help_text, 'dim', color)}")
        lines.append("")

    counts = {level: sum(1 for f in findings if f.severity == level) for level in (ERROR, WARNING, NOTE)}
    summary = f"{counts[ERROR]} errori, {counts[WARNING]} avvisi, {counts[NOTE]} note"
    lines.append(_paint(summary, "bold", color))
    return "\n".join(lines)


def render_json(findings: list[Finding], path: str) -> str:
    payload = {
        "file": path,
        "ok": not any(finding.severity == ERROR for finding in findings),
        "counts": {
            "error": sum(1 for f in findings if f.severity == ERROR),
            "warning": sum(1 for f in findings if f.severity == WARNING),
            "note": sum(1 for f in findings if f.severity == NOTE),
        },
        "findings": [finding.as_dict() for finding in findings],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def render_github(findings: list[Finding], path: str) -> str:
    level_map = {ERROR: "error", WARNING: "warning", NOTE: "notice"}
    lines = []
    for finding in findings:
        level = level_map[finding.severity]
        lines.append(
            f"::{level} file={path},line={finding.line},title={finding.code} {finding.title}::{finding.message}"
        )
    return "\n".join(lines)
