"""Le regole di analisi.

Ogni regola ha un codice stabile, una gravità e un testo che dice *perché* è un
problema: un avviso che non spiega la conseguenza viene silenziato, non risolto.
"""

from __future__ import annotations

import os
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from .parser import Dockerfile, Instruction

ERROR = "error"
WARNING = "warning"
NOTE = "note"

SEVERITY_ORDER = {ERROR: 0, WARNING: 1, NOTE: 2}


@dataclass(frozen=True)
class Finding:
    code: str
    severity: str
    title: str
    message: str
    line: int
    end_line: int = 0
    help_text: str = ""

    def as_dict(self) -> dict[str, object]:
        return {
            "code": self.code,
            "severity": self.severity,
            "title": self.title,
            "message": self.message,
            "line": self.line,
            "end_line": self.end_line or self.line,
            "help": self.help_text,
        }


@dataclass(frozen=True)
class Rule:
    code: str
    severity: str
    title: str
    help_text: str
    check: Callable[[Dockerfile, str | None], Iterable[Finding]]


_REGISTRY: list[Rule] = []


def rule(code: str, severity: str, title: str, help_text: str):
    def decorator(func):
        _REGISTRY.append(Rule(code, severity, title, help_text, func))
        return func

    return decorator


def _finding(rule_code: str, instruction: Instruction | None, message: str, line: int | None = None) -> Finding:
    definition = next(item for item in _REGISTRY if item.code == rule_code)
    start = line if line is not None else (instruction.line if instruction else 1)
    end = instruction.end_line if instruction else start
    return Finding(
        code=definition.code,
        severity=definition.severity,
        title=definition.title,
        message=message,
        line=start,
        end_line=end,
        help_text=definition.help_text,
    )


# --------------------------------------------------------------------------
# Immagine di base e riproducibilità
# --------------------------------------------------------------------------


@rule(
    "DW001",
    WARNING,
    "Immagine di base senza tag o con tag latest",
    "Con 'latest' la stessa build produce immagini diverse a distanza di giorni. "
    "Fissa una versione, meglio se un digest.",
)
def _base_image_tag(dockerfile: Dockerfile, context: str | None):
    aliases = {stage.alias for stage in dockerfile.stages if stage.alias}
    for stage in dockerfile.stages:
        if stage.image in aliases or stage.image == "scratch" or stage.image.startswith("$"):
            continue
        if stage.has_digest:
            continue
        if stage.tag is None:
            yield _finding("DW001", None, f"{stage.image} non ha un tag: verrà usato 'latest'", stage.line)
        elif stage.tag == "latest":
            yield _finding("DW001", None, f"{stage.image} usa il tag 'latest'", stage.line)


@rule(
    "DW002",
    NOTE,
    "Immagine di base non ancorata a un digest",
    "Un tag può essere ripubblicato puntando a un contenuto diverso. Il digest è l'unico riferimento immutabile.",
)
def _base_image_digest(dockerfile: Dockerfile, context: str | None):
    aliases = {stage.alias for stage in dockerfile.stages if stage.alias}
    for stage in dockerfile.stages:
        if stage.image in aliases or stage.image == "scratch" or stage.image.startswith("$"):
            continue
        if not stage.has_digest:
            yield _finding("DW002", None, f"{stage.image} è riferita per tag e non per digest", stage.line)


@rule(
    "DW003",
    WARNING,
    "Stage di build dichiarato e mai usato",
    "Uno stage che nessun COPY --from raggiunge viene comunque costruito da alcune "
    "configurazioni: è tempo speso per nulla.",
)
def _unused_stage(dockerfile: Dockerfile, context: str | None):
    if len(dockerfile.stages) < 2:
        return
    referenced = set()
    for instruction in dockerfile.of("COPY", "ADD"):
        source = instruction.flags.get("from")
        if source:
            referenced.add(source)
    for stage in dockerfile.stages[:-1]:
        name = stage.alias or str(stage.index)
        if name not in referenced and str(stage.index) not in referenced:
            yield _finding("DW003", None, f"lo stage {name!r} non è riferito da nessun COPY --from", stage.line)


# --------------------------------------------------------------------------
# Gestione dei pacchetti
# --------------------------------------------------------------------------

_APT_INSTALL = re.compile(r"\bapt(?:-get)?\s+(?:-[^\s]+\s+)*install\b")
_APT_UPDATE = re.compile(r"\bapt(?:-get)?\s+(?:-[^\s]+\s+)*update\b")


@rule(
    "DW010",
    WARNING,
    "apt-get install senza --no-install-recommends",
    "I pacchetti raccomandati aggiungono decine di megabyte e superficie di attacco che nessuno ha chiesto.",
)
def _apt_recommends(dockerfile: Dockerfile, context: str | None):
    for instruction in dockerfile.of("RUN"):
        if _APT_INSTALL.search(instruction.value) and "--no-install-recommends" not in instruction.value:
            yield _finding("DW010", instruction, "aggiungi --no-install-recommends a apt-get install")


@rule(
    "DW011",
    WARNING,
    "Cache di apt non ripulita nello stesso layer",
    "Cancellare /var/lib/apt/lists in un RUN successivo non riduce l'immagine: il layer precedente resta.",
)
def _apt_cache(dockerfile: Dockerfile, context: str | None):
    for instruction in dockerfile.of("RUN"):
        if _APT_INSTALL.search(instruction.value) and "/var/lib/apt/lists" not in instruction.value:
            yield _finding("DW011", instruction, "aggiungi 'rm -rf /var/lib/apt/lists/*' nello stesso RUN")


@rule(
    "DW012",
    ERROR,
    "apt-get update separato da apt-get install",
    "Il layer di update viene riusato dalla cache mentre install è nuovo: "
    "si installano pacchetti da un indice vecchio.",
)
def _apt_update_split(dockerfile: Dockerfile, context: str | None):
    runs = dockerfile.of("RUN")
    for index, instruction in enumerate(runs):
        if not _APT_UPDATE.search(instruction.value) or _APT_INSTALL.search(instruction.value):
            continue
        later = any(_APT_INSTALL.search(other.value) for other in runs[index + 1 :])
        if later:
            yield _finding("DW012", instruction, "unisci 'apt-get update' e 'apt-get install' in un solo RUN")


@rule(
    "DW013",
    WARNING,
    "apk add senza --no-cache",
    "Senza --no-cache l'indice dei pacchetti resta nell'immagine finale.",
)
def _apk_cache(dockerfile: Dockerfile, context: str | None):
    for instruction in dockerfile.of("RUN"):
        if re.search(r"\bapk\s+(?:-[^\s]+\s+)*add\b", instruction.value) and "--no-cache" not in instruction.value:
            yield _finding("DW013", instruction, "aggiungi --no-cache a apk add")


@rule(
    "DW014",
    NOTE,
    "pip install senza --no-cache-dir",
    "La cache di pip resta nell'immagine e non serve a nessuno in produzione.",
)
def _pip_cache(dockerfile: Dockerfile, context: str | None):
    for instruction in dockerfile.of("RUN"):
        if re.search(r"\bpip3?\s+install\b", instruction.value) and "--no-cache-dir" not in instruction.value:
            yield _finding("DW014", instruction, "aggiungi --no-cache-dir a pip install")


@rule(
    "DW015",
    WARNING,
    "npm install invece di npm ci",
    "npm install può aggiornare il lockfile durante la build: due build dello stesso commit installano alberi diversi.",
)
def _npm_ci(dockerfile: Dockerfile, context: str | None):
    for instruction in dockerfile.of("RUN"):
        if re.search(r"\bnpm\s+install\b", instruction.value) and "--production" not in instruction.value:
            yield _finding("DW015", instruction, "usa 'npm ci', che rispetta package-lock.json senza modificarlo")


# --------------------------------------------------------------------------
# Cache e struttura dei layer
# --------------------------------------------------------------------------


@rule(
    "DW020",
    WARNING,
    "Sorgenti copiate prima delle dipendenze",
    "Un COPY dell'intero contesto prima dell'installazione invalida la cache a ogni modifica del codice.",
)
def _copy_before_deps(dockerfile: Dockerfile, context: str | None):
    installers = re.compile(r"\b(npm|yarn|pnpm|pip3?|poetry|bundle|composer|go\s+mod|cargo)\b")
    for stage in dockerfile.stages:
        broad_copy = None
        for instruction in stage.instructions:
            if instruction.keyword == "RUN" and installers.search(instruction.value):
                # Le dipendenze sono già state installate prima della copia larga:
                # è esattamente l'ordine consigliato, non c'è nulla da segnalare.
                if broad_copy is None:
                    break
                yield _finding(
                    "DW020",
                    broad_copy,
                    "copia prima i soli file di dipendenze, installa, poi copia il resto del codice",
                )
                break
            if instruction.keyword in {"COPY", "ADD"} and instruction.words[:1] in (["."], ["./"]):
                broad_copy = broad_copy or instruction


@rule(
    "DW021",
    NOTE,
    "Contesto di build senza .dockerignore",
    "Senza .dockerignore finiscono nel contesto .git, node_modules e file di ambiente: "
    "build lente e segreti a rischio.",
)
def _dockerignore(dockerfile: Dockerfile, context: str | None):
    if context is None:
        return
    if not os.path.exists(os.path.join(context, ".dockerignore")):
        yield _finding("DW021", None, "aggiungi un .dockerignore accanto al Dockerfile", 1)


@rule(
    "DW022",
    NOTE,
    "Istruzioni RUN consecutive che potrebbero essere unite",
    "Ogni RUN è un layer. Una catena lunga di comandi brevi gonfia l'immagine senza dare nulla in cambio.",
)
def _consecutive_runs(dockerfile: Dockerfile, context: str | None):
    threshold = 4
    streak: list[Instruction] = []
    for instruction in [*dockerfile.instructions, Instruction("END", "", 0, 0)]:
        if instruction.keyword == "RUN":
            streak.append(instruction)
            continue
        if len(streak) > threshold:
            yield _finding(
                "DW022",
                streak[0],
                f"{len(streak)} RUN consecutivi: valuta di unirli con && per ridurre i layer",
            )
        streak = []


# --------------------------------------------------------------------------
# Sicurezza
# --------------------------------------------------------------------------

_SECRET_NAME = re.compile(r"(PASSWORD|PASSWD|SECRET|TOKEN|APIKEY|API_KEY|ACCESS_KEY|PRIVATE_KEY|CREDENTIAL)", re.I)


@rule(
    "DW030",
    ERROR,
    "Il container gira come root",
    "Senza una USER non privilegiata, una falla nel processo diventa root nel container e confina solo con il kernel.",
)
def _runs_as_root(dockerfile: Dockerfile, context: str | None):
    final = dockerfile.final_stage
    if final is None:
        return
    users = [item for item in final.instructions if item.keyword == "USER"]
    if not users:
        yield _finding(
            "DW030", None, "lo stage finale non dichiara nessuna USER: il processo parte come root", final.line
        )
    elif users[-1].value.split(":")[0].strip() in {"root", "0"}:
        yield _finding("DW030", users[-1], "l'ultima USER dello stage finale è root")


@rule(
    "DW031",
    ERROR,
    "Segreto scritto in ENV o ARG",
    "I valori di ENV e ARG restano nella storia dei layer: chiunque abbia l'immagine li rilegge con 'docker history'.",
)
def _secrets_in_env(dockerfile: Dockerfile, context: str | None):
    for instruction in dockerfile.of("ENV", "ARG"):
        for name, value in _pairs(instruction.value):
            if _SECRET_NAME.search(name) and value and not value.startswith("$"):
                yield _finding(
                    "DW031",
                    instruction,
                    f"{name} contiene un valore in chiaro: usa un secret di build o una variabile a runtime",
                )


def _pairs(value: str) -> list[tuple[str, str]]:
    """Legge la forma 'CHIAVE=valore' ripetuta e la forma legacy 'CHIAVE valore'."""
    words = value.split()
    if not words:
        return []
    if "=" not in words[0]:
        return [(words[0], " ".join(words[1:]))]
    pairs = []
    for word in words:
        name, sep, val = word.partition("=")
        if sep:
            pairs.append((name, val.strip("\"'")))
    return pairs


@rule(
    "DW032",
    ERROR,
    "Script remoto eseguito senza verifica",
    "Una pipe da rete a shell esegue codice che nessuno ha letto e che può cambiare tra una build e l'altra.",
)
def _curl_pipe_shell(dockerfile: Dockerfile, context: str | None):
    pattern = re.compile(r"\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba|z|k)?sh\b")
    for instruction in dockerfile.of("RUN"):
        if pattern.search(instruction.value):
            yield _finding("DW032", instruction, "scarica, verifica la somma di controllo, poi esegui")


@rule(
    "DW033",
    WARNING,
    "Permessi 777",
    "chmod 777 rende il file scrivibile da qualunque processo del container: annulla ogni separazione di privilegi.",
)
def _chmod_777(dockerfile: Dockerfile, context: str | None):
    for instruction in dockerfile.of("RUN"):
        if re.search(r"\bchmod\s+(-[A-Za-z]+\s+)*(0?777|a\+rwx)\b", instruction.value):
            yield _finding("DW033", instruction, "assegna il proprietario giusto invece di aprire i permessi a tutti")


@rule(
    "DW034",
    NOTE,
    "sudo dentro un RUN",
    "La build gira già come root: sudo aggiunge un pacchetto e un binario setuid all'immagine, senza motivo.",
)
def _sudo(dockerfile: Dockerfile, context: str | None):
    for instruction in dockerfile.of("RUN"):
        if re.search(r"(^|\s)sudo\s", instruction.value):
            yield _finding("DW034", instruction, "rimuovi sudo e usa USER per cambiare utente")


@rule(
    "DW035",
    WARNING,
    "ADD usato al posto di COPY",
    "ADD estrae archivi e scarica URL: comportamenti impliciti che sorprendono. Per copiare file serve COPY.",
)
def _add_instead_of_copy(dockerfile: Dockerfile, context: str | None):
    for instruction in dockerfile.of("ADD"):
        words = instruction.words
        if not words:
            continue
        source = words[0]
        if source.startswith(("http://", "https://", "git@")):
            yield _finding(
                "DW035", instruction, "ADD da URL non verifica nulla: usa RUN curl con controllo della somma"
            )
        elif not source.endswith((".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".zip")):
            yield _finding("DW035", instruction, "usa COPY: qui ADD non porta nessun vantaggio")


# --------------------------------------------------------------------------
# Esecuzione
# --------------------------------------------------------------------------


@rule(
    "DW040",
    WARNING,
    "CMD o ENTRYPOINT in forma shell",
    "In forma shell il processo gira sotto /bin/sh -c e non riceve SIGTERM: "
    "il container muore per timeout invece che per arresto pulito.",
)
def _shell_form(dockerfile: Dockerfile, context: str | None):
    for instruction in dockerfile.of("CMD", "ENTRYPOINT"):
        if not instruction.value.strip().startswith("["):
            yield _finding(
                "DW040", instruction, f'usa la forma esec: {instruction.keyword} ["eseguibile", "argomento"]'
            )


@rule(
    "DW041",
    NOTE,
    "Nessun HEALTHCHECK",
    "Senza healthcheck l'orchestratore considera vivo un container che ha smesso di rispondere.",
)
def _healthcheck(dockerfile: Dockerfile, context: str | None):
    final = dockerfile.final_stage
    if final is None:
        return
    if not any(item.keyword == "HEALTHCHECK" for item in final.instructions):
        yield _finding("DW041", None, "aggiungi un HEALTHCHECK allo stage finale", final.line)


@rule(
    "DW042",
    WARNING,
    "cd dentro RUN invece di WORKDIR",
    "Il cd vale solo per quel layer: l'istruzione successiva riparte dalla directory precedente.",
)
def _cd_instead_of_workdir(dockerfile: Dockerfile, context: str | None):
    for instruction in dockerfile.of("RUN"):
        if re.match(r"^\s*cd\s+[^\s;&|]+\s*$", instruction.value):
            yield _finding("DW042", instruction, "usa WORKDIR: il cambio di directory persiste tra le istruzioni")


@rule(
    "DW043",
    WARNING,
    "EXPOSE con porta non valida",
    "Una porta fuori intervallo o non numerica fa fallire la build, e il messaggio del daemon non è chiarissimo.",
)
def _expose_ports(dockerfile: Dockerfile, context: str | None):
    for instruction in dockerfile.of("EXPOSE"):
        for word in instruction.words:
            port = word.split("/")[0]
            if port.startswith("$"):
                continue
            if not port.isdigit() or not 1 <= int(port) <= 65535:
                yield _finding("DW043", instruction, f"porta non valida: {word!r}")


@rule(
    "DW044",
    NOTE,
    "MAINTAINER è deprecato",
    "MAINTAINER è stato sostituito da LABEL org.opencontainers.image.authors, che finisce nei metadati standard.",
)
def _maintainer(dockerfile: Dockerfile, context: str | None):
    for instruction in dockerfile.of("MAINTAINER"):
        yield _finding("DW044", instruction, 'usa LABEL org.opencontainers.image.authors="..."')


@rule(
    "DW045",
    ERROR,
    "Errori di sintassi nel Dockerfile",
    "Una parola chiave sconosciuta o una continuazione senza seguito fa fallire la build prima di qualunque comando.",
)
def _syntax(dockerfile: Dockerfile, context: str | None):
    for line, message in dockerfile.errors:
        yield _finding("DW045", None, message, line)


@rule(
    "DW046",
    ERROR,
    "Nessuna istruzione FROM",
    "Un Dockerfile senza FROM non descrive nessuna immagine: la build fallisce immediatamente.",
)
def _needs_from(dockerfile: Dockerfile, context: str | None):
    if not dockerfile.stages:
        yield _finding("DW046", None, "il file non contiene nessuna istruzione FROM", 1)


def all_rules() -> list[Rule]:
    return sorted(_REGISTRY, key=lambda item: item.code)


def analyze(dockerfile: Dockerfile, *, context: str | None = None, disabled: set[str] | None = None) -> list[Finding]:
    """Applica tutte le regole, rispettando le soppressioni inline e la lista esclusi."""
    excluded = disabled or set()
    suppressed_lines = {
        instruction.line: instruction
        for instruction in dockerfile.instructions
        if instruction.ignored or instruction.ignore_all
    }

    findings: list[Finding] = []
    for definition in _REGISTRY:
        if definition.code in excluded:
            continue
        for finding in definition.check(dockerfile, context):
            instruction = suppressed_lines.get(finding.line)
            if instruction is not None and instruction.suppresses(finding.code):
                continue
            findings.append(finding)

    return sorted(findings, key=lambda item: (item.line, SEVERITY_ORDER[item.severity], item.code))
