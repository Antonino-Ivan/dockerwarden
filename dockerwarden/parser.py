"""Parser di Dockerfile.

Copre ciò che serve per analizzare un file reale: direttive iniziali, carattere
di escape configurabile, continuazioni di riga, commenti interni a una
istruzione continuata, heredoc BuildKit e stage multipli con alias.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Istruzioni ammesse dal formato. Una parola chiave fuori da questo insieme è un
# refuso: il daemon fallirebbe la build, quindi conviene dirlo subito.
KEYWORDS = {
    "ADD",
    "ARG",
    "CMD",
    "COPY",
    "ENTRYPOINT",
    "ENV",
    "EXPOSE",
    "FROM",
    "HEALTHCHECK",
    "LABEL",
    "MAINTAINER",
    "ONBUILD",
    "RUN",
    "SHELL",
    "STOPSIGNAL",
    "USER",
    "VOLUME",
    "WORKDIR",
}

_DIRECTIVE = re.compile(r"^#\s*(syntax|escape|check)\s*=\s*(.+?)\s*$", re.IGNORECASE)
_FLAG = re.compile(r"^--([A-Za-z][A-Za-z0-9-]*)(?:=(.*))?$")
_HEREDOC = re.compile(r"<<-?\s*['\"]?([A-Za-z_][A-Za-z0-9_]*)['\"]?")
_IGNORE = re.compile(r"#\s*dockerwarden:ignore(?:=([A-Z0-9, ]+))?", re.IGNORECASE)


@dataclass
class Instruction:
    keyword: str
    value: str
    line: int
    end_line: int
    flags: dict[str, str] = field(default_factory=dict)
    ignored: tuple[str, ...] = ()
    ignore_all: bool = False

    @property
    def words(self) -> list[str]:
        return self.value.split()

    def suppresses(self, code: str) -> bool:
        return self.ignore_all or code in self.ignored


@dataclass
class Stage:
    """Uno stage di build: da un FROM al successivo."""

    image: str
    alias: str | None
    index: int
    line: int
    instructions: list[Instruction] = field(default_factory=list)

    @property
    def base_name(self) -> str:
        return self.image.split(":")[0].split("@")[0]

    @property
    def tag(self) -> str | None:
        without_digest = self.image.split("@")[0]
        if ":" not in without_digest:
            return None
        return without_digest.rsplit(":", 1)[1]

    @property
    def has_digest(self) -> bool:
        return "@sha256:" in self.image


@dataclass
class Dockerfile:
    instructions: list[Instruction] = field(default_factory=list)
    stages: list[Stage] = field(default_factory=list)
    directives: dict[str, str] = field(default_factory=dict)
    errors: list[tuple[int, str]] = field(default_factory=list)
    path: str = "Dockerfile"

    def of(self, *keywords: str) -> list[Instruction]:
        wanted = {keyword.upper() for keyword in keywords}
        return [item for item in self.instructions if item.keyword in wanted]

    @property
    def final_stage(self) -> Stage | None:
        return self.stages[-1] if self.stages else None


def _read_directives(lines: list[str]) -> tuple[dict[str, str], int]:
    """Le direttive valgono solo finché non compare la prima riga non commentata."""
    directives: dict[str, str] = {}
    index = 0
    for index, raw in enumerate(lines):
        stripped = raw.strip()
        if not stripped:
            continue
        if not stripped.startswith("#"):
            return directives, index
        match = _DIRECTIVE.match(stripped)
        if match:
            directives[match.group(1).lower()] = match.group(2)
        else:
            return directives, index
    return directives, index + 1


def _split_flags(value: str) -> tuple[dict[str, str], str]:
    flags: dict[str, str] = {}
    words = value.split()
    consumed = 0
    for word in words:
        match = _FLAG.match(word)
        if not match:
            break
        flags[match.group(1).lower()] = match.group(2) if match.group(2) is not None else "true"
        consumed += 1
    return flags, " ".join(words[consumed:])


def _collect_suppressions(text: str) -> tuple[tuple[str, ...], bool]:
    match = _IGNORE.search(text)
    if not match:
        return (), False
    codes = match.group(1)
    if not codes:
        return (), True
    return tuple(code.strip().upper() for code in codes.split(",") if code.strip()), False


def parse(text: str, path: str = "Dockerfile") -> Dockerfile:
    lines = text.splitlines()
    directives, start = _read_directives(lines)
    escape = directives.get("escape", "\\")[:1] or "\\"

    result = Dockerfile(directives=directives, path=path)
    index = start
    while index < len(lines):
        raw = lines[index]
        first_line = index + 1
        stripped = raw.strip()
        index += 1

        if not stripped or stripped.startswith("#"):
            continue

        # Continuazione: si accumula finché la riga non termina con l'escape.
        # I commenti interni a una continuazione vengono scartati, come fa Docker.
        parts = [stripped]
        while parts[-1].endswith(escape):
            parts[-1] = parts[-1][:-1].rstrip()
            if index >= len(lines):
                result.errors.append((first_line, "continuazione di riga senza seguito"))
                break
            nxt = lines[index].strip()
            index += 1
            if nxt.startswith("#"):
                parts.append(escape)  # mantiene aperta la continuazione
                continue
            parts.append(nxt)

        joined = " ".join(part for part in parts if part != escape).strip()
        keyword, _, rest = joined.partition(" ")
        keyword = keyword.upper()

        if keyword not in KEYWORDS:
            result.errors.append((first_line, f"istruzione sconosciuta: {keyword!r}"))
            continue

        # Heredoc BuildKit: il corpo appartiene all'istruzione, non è codice a sé.
        heredoc = _HEREDOC.search(rest)
        if heredoc:
            terminator = heredoc.group(1)
            body: list[str] = []
            while index < len(lines) and lines[index].strip() != terminator:
                body.append(lines[index])
                index += 1
            index += 1  # consuma il terminatore
            rest = rest + " " + " ".join(line.strip() for line in body)

        flags, value = _split_flags(rest.strip())
        ignored, ignore_all = _collect_suppressions(raw)
        instruction = Instruction(
            keyword=keyword,
            value=value,
            line=first_line,
            end_line=index,
            flags=flags,
            ignored=ignored,
            ignore_all=ignore_all,
        )
        result.instructions.append(instruction)

    result.stages = _build_stages(result.instructions)
    return result


def _build_stages(instructions: list[Instruction]) -> list[Stage]:
    stages: list[Stage] = []
    for instruction in instructions:
        if instruction.keyword == "FROM":
            words = instruction.words
            image = words[0] if words else ""
            alias = None
            if len(words) >= 3 and words[1].upper() == "AS":
                alias = words[2]
            stages.append(Stage(image=image, alias=alias, index=len(stages), line=instruction.line))
        elif stages:
            stages[-1].instructions.append(instruction)
    return stages


def parse_file(path: str) -> Dockerfile:
    with open(path, encoding="utf-8") as handle:
        return parse(handle.read(), path=path)
