"""Permette `python -m dockerwarden` oltre allo script installato."""

from .cli import main

raise SystemExit(main())
