"""Serializzazione in SARIF 2.1.0, il formato che GitHub code scanning accetta."""

from __future__ import annotations

import json

from . import __version__
from .rules import Finding, all_rules

SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"

# SARIF conosce error/warning/note/none: la gravità interna usa gli stessi nomi
# proprio per non dover tradurre nulla qui.
_LEVELS = {"error", "warning", "note", "none"}


def _rule_descriptor(rule) -> dict:
    return {
        "id": rule.code,
        "name": rule.code,
        "shortDescription": {"text": rule.title},
        "fullDescription": {"text": rule.help_text},
        "help": {"text": rule.help_text, "markdown": f"**{rule.title}**\n\n{rule.help_text}"},
        "defaultConfiguration": {"level": rule.severity if rule.severity in _LEVELS else "warning"},
        "properties": {"tags": ["docker", "container", "infrastructure"]},
    }


def _result(finding: Finding, path: str) -> dict:
    return {
        "ruleId": finding.code,
        "level": finding.severity if finding.severity in _LEVELS else "warning",
        "message": {"text": f"{finding.title}: {finding.message}"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": path},
                    "region": {
                        "startLine": max(finding.line, 1),
                        "endLine": max(finding.end_line or finding.line, finding.line, 1),
                    },
                }
            }
        ],
    }


def render(findings: list[Finding], path: str) -> str:
    document = {
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "dockerwarden",
                        "version": __version__,
                        "informationUri": "https://github.com/Antonino-Ivan/dockerwarden",
                        "rules": [_rule_descriptor(rule) for rule in all_rules()],
                    }
                },
                "results": [_result(finding, path) for finding in findings],
            }
        ],
    }
    return json.dumps(document, indent=2, ensure_ascii=False)
