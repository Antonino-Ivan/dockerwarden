# dockerwarden

Un Dockerfile che si costruisce non è un Dockerfile corretto.

dockerwarden legge un Dockerfile e dice cosa romperà: la riproducibilità (`FROM node:latest`), la cache (`apt-get update` in un layer, `install` nell'altro), la dimensione dell'immagine (la cache di apt lasciata dentro), la sicurezza (il processo che gira come root, il token scritto in una `ENV`, lo script scaricato da rete e passato a `sh`).

Venticinque regole, ognuna con un codice stabile e una spiegazione del **perché**. Zero dipendenze: parser, regole e resa SARIF stanno tutti nella libreria standard.

```
$ dockerwarden lint Dockerfile
errore  DW030  Il container gira come root
        lo stage finale non dichiara nessuna USER: il processo parte come root
        Dockerfile:2

errore  DW031  Segreto scritto in ENV o ARG
        DATABASE_PASSWORD contiene un valore in chiaro: usa un secret di build o una variabile a runtime
        Dockerfile:6

errore  DW012  apt-get update separato da apt-get install
        unisci 'apt-get update' e 'apt-get install' in un solo RUN
        Dockerfile:9

5 errori, 10 avvisi, 5 note
```

## Installazione

```bash
pip install dockerwarden
```

## Uso

```bash
dockerwarden lint                                  # analizza ./Dockerfile
dockerwarden lint deploy/Dockerfile --explain      # con la spiegazione estesa
dockerwarden lint Dockerfile --min-severity error  # mostra solo gli errori
dockerwarden lint Dockerfile --fail-on warning     # fallisce anche sugli avvisi
dockerwarden lint Dockerfile --disable DW002 --disable DW041
dockerwarden lint Dockerfile -f sarif -o dockerwarden.sarif
dockerwarden rules -v                              # elenco completo delle regole
```

### Soppressione puntuale

Un commento sulla riga dell'istruzione, quando la regola in quel caso specifico non si applica:

```dockerfile
RUN apt-get install -y ./pacchetto-locale.deb  # dockerwarden:ignore=DW010
RUN comando-particolare                        # dockerwarden:ignore
```

## Le regole

### Immagine di base e riproducibilità

| Codice | Gravità | Problema |
| --- | --- | --- |
| `DW001` | avviso | immagine senza tag o con `latest`: la stessa build cambia risultato nel tempo |
| `DW002` | nota | immagine riferita per tag e non per digest: un tag può essere ripubblicato |
| `DW003` | avviso | stage di build dichiarato e mai raggiunto da un `COPY --from` |
| `DW046` | errore | nessuna istruzione `FROM` |

### Gestione dei pacchetti

| Codice | Gravità | Problema |
| --- | --- | --- |
| `DW010` | avviso | `apt-get install` senza `--no-install-recommends` |
| `DW011` | avviso | cache di apt non rimossa nello stesso layer |
| `DW012` | errore | `apt-get update` in un `RUN` separato da `install`: si installa da un indice preso dalla cache |
| `DW013` | avviso | `apk add` senza `--no-cache` |
| `DW014` | nota | `pip install` senza `--no-cache-dir` |
| `DW015` | avviso | `npm install` invece di `npm ci` |

### Cache e layer

| Codice | Gravità | Problema |
| --- | --- | --- |
| `DW020` | avviso | l'intero contesto copiato prima di installare le dipendenze |
| `DW021` | nota | manca un `.dockerignore` accanto al Dockerfile |
| `DW022` | nota | più di quattro `RUN` consecutivi |

### Sicurezza

| Codice | Gravità | Problema |
| --- | --- | --- |
| `DW030` | errore | lo stage finale gira come root |
| `DW031` | errore | segreto in chiaro in `ENV` o `ARG`: resta leggibile con `docker history` |
| `DW032` | errore | script remoto passato a shell senza verifica |
| `DW033` | avviso | `chmod 777` |
| `DW034` | nota | `sudo` dentro un `RUN` |
| `DW035` | avviso | `ADD` usato dove basta `COPY`, o `ADD` da URL |

### Esecuzione

| Codice | Gravità | Problema |
| --- | --- | --- |
| `DW040` | avviso | `CMD`/`ENTRYPOINT` in forma shell: il processo non riceve `SIGTERM` |
| `DW041` | nota | nessun `HEALTHCHECK` |
| `DW042` | avviso | `cd` dentro un `RUN` invece di `WORKDIR` |
| `DW043` | avviso | porta di `EXPOSE` non valida |
| `DW044` | nota | `MAINTAINER`, deprecato |
| `DW045` | errore | errori di sintassi: parola chiave sconosciuta, continuazione senza seguito |

## Integrazione con GitHub code scanning

I risultati in SARIF 2.1.0 compaiono nella scheda Security del repository, con riga, gravità e spiegazione:

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: actions/checkout@v4
  - uses: actions/setup-python@v5
    with:
      python-version: "3.12"

  - uses: Antonino-Ivan/dockerwarden@v1
    id: warden
    continue-on-error: true
    with:
      file: Dockerfile
      sarif: dockerwarden.sarif

  - uses: github/codeql-action/upload-sarif@v3
    with:
      sarif_file: ${{ steps.warden.outputs.sarif-file }}
```

`continue-on-error` serve perché il SARIF va caricato anche — soprattutto — quando l'analisi trova qualcosa.

## Che cosa capisce il parser

Non è una ricerca per espressioni regolari sul testo grezzo. Il parser gestisce:

- direttive iniziali `# syntax=` e `# escape=`, con carattere di escape configurabile
- continuazioni di riga, compresi i commenti inseriti in mezzo a una continuazione
- flag di istruzione (`COPY --from=build --chown=node:node`) separati dagli argomenti
- heredoc BuildKit (`RUN <<EOF … EOF`), il cui corpo appartiene all'istruzione
- stage multipli con alias, tag e digest analizzati separatamente

Le istruzioni sconosciute non vengono ignorate: diventano `DW045`, perché sono lo stesso errore che farà fallire la build.

## Come è fatto

| File | Responsabilità |
| --- | --- |
| `dockerwarden/parser.py` | dal testo alla struttura: istruzioni, flag, stage, direttive |
| `dockerwarden/rules.py` | le venticinque regole, registrate con codice, gravità e spiegazione |
| `dockerwarden/sarif.py` | documento SARIF 2.1.0 con i descrittori di tutte le regole |
| `dockerwarden/report.py` | testo, JSON, annotazioni GitHub |
| `dockerwarden/cli.py` | comandi, filtri di gravità, soglia di fallimento |

Aggiungere una regola è una funzione con un decoratore: codice, gravità, titolo, spiegazione, e un generatore che produce le segnalazioni.

## Sviluppo

```bash
python -m pip install -e .
python -m unittest discover -s tests -t .
ruff check .
```

80 test: parser, ogni singola regola nei casi positivo e negativo, validità dello schema SARIF, riga di comando.

## Licenza

MIT — vedi [LICENSE](LICENSE).
