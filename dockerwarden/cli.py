"""Interfaccia a riga di comando di dockerwarden."""

from __future__ import annotations

import argparse
import os
import sys

from . import __version__
from .parser import parse_file
from .report import render_github, render_json, render_text
from .rules import ERROR, NOTE, WARNING, all_rules, analyze
from .sarif import render as render_sarif

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2

DEFAULT_FILE = "Dockerfile"
SEVERITIES = (ERROR, WARNING, NOTE)


def _cmd_lint(args: argparse.Namespace) -> int:
    try:
        dockerfile = parse_file(args.file)
    except OSError as exc:
        print(f"Dockerfile non leggibile: {exc}", file=sys.stderr)
        return EXIT_USAGE

    context = args.context if args.context is not None else os.path.dirname(os.path.abspath(args.file))
    disabled = {code.strip().upper() for code in (args.disable or []) if code.strip()}

    unknown = disabled - {rule.code for rule in all_rules()}
    if unknown:
        print(f"codici inesistenti in --disable: {', '.join(sorted(unknown))}", file=sys.stderr)
        return EXIT_USAGE

    findings = analyze(dockerfile, context=context, disabled=disabled)

    minimum = SEVERITIES.index(args.min_severity)
    findings = [finding for finding in findings if SEVERITIES.index(finding.severity) <= minimum]

    display = os.path.relpath(args.file).replace(os.sep, "/")

    # Le annotazioni sono comandi di workflow: GitHub le legge solo dallo stdout
    # del passo, quindi restano separate dal report scritto su file.
    if args.annotate and args.format != "github":
        annotations = render_github(findings, display)
        if annotations:
            print(annotations)

    if args.format == "json":
        rendered = render_json(findings, display)
    elif args.format == "sarif":
        rendered = render_sarif(findings, display)
    elif args.format == "github":
        rendered = render_github(findings, display)
    else:
        rendered = render_text(findings, display, explain=args.explain)

    if args.output and args.output != "-":
        try:
            with open(args.output, "w", encoding="utf-8") as handle:
                handle.write(rendered if rendered.endswith("\n") else rendered + "\n")
        except OSError as exc:
            print(f"scrittura del report fallita: {exc}", file=sys.stderr)
            return EXIT_USAGE
        print(f"report scritto in {args.output}", file=sys.stderr)
    elif rendered:
        print(rendered)

    threshold = SEVERITIES.index(args.fail_on)
    failing = [finding for finding in findings if SEVERITIES.index(finding.severity) <= threshold]
    return EXIT_FINDINGS if failing else EXIT_OK


def _cmd_rules(args: argparse.Namespace) -> int:
    for rule in all_rules():
        print(f"{rule.code}  {rule.severity:8}  {rule.title}")
        if args.verbose:
            print(f"          {rule.help_text}\n")
    print(f"\n{len(all_rules())} regole")
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dockerwarden",
        description="Analizza un Dockerfile e segnala ciò che romperà build, cache o sicurezza.",
    )
    parser.add_argument("--version", action="version", version=f"dockerwarden {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    lint = sub.add_parser("lint", help="analizza un Dockerfile")
    lint.add_argument("file", nargs="?", default=DEFAULT_FILE, help=f"file da analizzare (default: {DEFAULT_FILE})")
    lint.add_argument("-f", "--format", choices=("text", "json", "sarif", "github"), default="text")
    lint.add_argument("--explain", action="store_true", help="mostra la spiegazione estesa di ogni regola")
    lint.add_argument("-o", "--output", default=None, help="scrive il report su file invece che a schermo")
    lint.add_argument(
        "--annotate",
        action="store_true",
        help="emette anche le annotazioni GitHub Actions: da usare con --output per non mescolarle al report",
    )
    lint.add_argument("--disable", action="append", metavar="CODICE", help="disattiva una regola, ripetibile")
    lint.add_argument(
        "--min-severity",
        choices=SEVERITIES,
        default=NOTE,
        help="mostra solo i problemi di gravità pari o superiore (default: note)",
    )
    lint.add_argument(
        "--fail-on",
        choices=SEVERITIES,
        default=ERROR,
        help="gravità che fa uscire con codice 1 (default: error)",
    )
    lint.add_argument(
        "--context",
        default=None,
        help="cartella del contesto di build, per i controlli che la riguardano (default: quella del Dockerfile)",
    )
    lint.set_defaults(func=_cmd_lint)

    rules = sub.add_parser("rules", help="elenca le regole disponibili")
    rules.add_argument("-v", "--verbose", action="store_true", help="mostra anche la spiegazione")
    rules.set_defaults(func=_cmd_rules)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
