import os
import tempfile
import unittest

from dockerwarden.parser import parse
from dockerwarden.rules import all_rules, analyze

BASE = "FROM alpine:3.20\nUSER app\n"


def codes(text, **kwargs):
    return [finding.code for finding in analyze(parse(text), **kwargs)]


class BaseImage(unittest.TestCase):
    def test_tag_latest(self):
        self.assertIn("DW001", codes("FROM node:latest\nUSER app\n"))

    def test_senza_tag(self):
        self.assertIn("DW001", codes("FROM node\nUSER app\n"))

    def test_tag_fissato_non_segnala(self):
        self.assertNotIn("DW001", codes("FROM node:22.12.0-slim\nUSER app\n"))

    def test_scratch_esente(self):
        self.assertNotIn("DW001", codes("FROM scratch\nUSER app\n"))

    def test_alias_interno_non_e_una_immagine_esterna(self):
        text = "FROM node:22.1 AS build\nFROM build\nUSER app\nCOPY --from=build /a /b\n"
        self.assertNotIn("DW001", codes(text))

    def test_digest_richiesto_come_nota(self):
        self.assertIn("DW002", codes("FROM node:22.12.0\nUSER app\n"))
        self.assertNotIn("DW002", codes("FROM node:22.12.0@sha256:abc\nUSER app\n"))

    def test_stage_mai_usato(self):
        text = "FROM node:22.1@sha256:a AS build\nRUN echo\nFROM node:22.1@sha256:a\nUSER app\n"
        self.assertIn("DW003", codes(text))

    def test_stage_usato_non_segnala(self):
        text = (
            "FROM node:22.1@sha256:a AS build\nRUN echo\nFROM node:22.1@sha256:a\nUSER app\nCOPY --from=build /a /b\n"
        )
        self.assertNotIn("DW003", codes(text))

    def test_senza_from(self):
        self.assertIn("DW046", codes("RUN echo ciao\n"))


class Packages(unittest.TestCase):
    def test_apt_senza_no_install_recommends(self):
        self.assertIn("DW010", codes(BASE + "RUN apt-get update && apt-get install -y curl\n"))

    def test_apt_completo_non_segnala(self):
        text = (
            BASE
            + "RUN apt-get update && apt-get install --no-install-recommends -y curl && rm -rf /var/lib/apt/lists/*\n"
        )
        found = codes(text)
        self.assertNotIn("DW010", found)
        self.assertNotIn("DW011", found)

    def test_cache_apt_non_ripulita(self):
        self.assertIn("DW011", codes(BASE + "RUN apt-get install --no-install-recommends -y curl\n"))

    def test_update_separato_da_install(self):
        self.assertIn("DW012", codes(BASE + "RUN apt-get update\nRUN apt-get install -y curl\n"))

    def test_update_e_install_insieme_non_segnalano(self):
        self.assertNotIn("DW012", codes(BASE + "RUN apt-get update && apt-get install -y curl\n"))

    def test_apk_senza_no_cache(self):
        self.assertIn("DW013", codes(BASE + "RUN apk add curl\n"))
        self.assertNotIn("DW013", codes(BASE + "RUN apk add --no-cache curl\n"))

    def test_pip_senza_no_cache_dir(self):
        self.assertIn("DW014", codes(BASE + "RUN pip install requests\n"))
        self.assertNotIn("DW014", codes(BASE + "RUN pip install --no-cache-dir requests\n"))

    def test_npm_install_invece_di_ci(self):
        self.assertIn("DW015", codes(BASE + "RUN npm install\n"))
        self.assertNotIn("DW015", codes(BASE + "RUN npm ci\n"))


class LayersAndCache(unittest.TestCase):
    def test_copia_larga_prima_delle_dipendenze(self):
        self.assertIn("DW020", codes(BASE + "COPY . .\nRUN npm ci\n"))

    def test_ordine_corretto_non_segnala(self):
        text = BASE + "COPY package.json package-lock.json ./\nRUN npm ci\nCOPY . .\nRUN npm run build\n"
        self.assertNotIn("DW020", codes(text))

    def test_dockerignore_mancante(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertIn("DW021", codes(BASE, context=directory))
            open(os.path.join(directory, ".dockerignore"), "w").close()
            self.assertNotIn("DW021", codes(BASE, context=directory))

    def test_troppi_run_consecutivi(self):
        text = BASE + "".join(f"RUN echo {n}\n" for n in range(6))
        self.assertIn("DW022", codes(text))

    def test_pochi_run_non_segnalano(self):
        self.assertNotIn("DW022", codes(BASE + "RUN echo uno\nRUN echo due\n"))


class Security(unittest.TestCase):
    def test_nessuna_user(self):
        self.assertIn("DW030", codes("FROM alpine:3.20\nRUN echo\n"))

    def test_user_root_esplicita(self):
        self.assertIn("DW030", codes("FROM alpine:3.20\nUSER app\nUSER root\n"))

    def test_user_non_privilegiata(self):
        self.assertNotIn("DW030", codes("FROM alpine:3.20\nUSER app\n"))

    def test_segreto_in_env(self):
        self.assertIn("DW031", codes(BASE + "ENV API_TOKEN=abc123\n"))

    def test_segreto_in_arg(self):
        self.assertIn("DW031", codes(BASE + "ARG DB_PASSWORD=segreta\n"))

    def test_variabile_non_sospetta(self):
        self.assertNotIn("DW031", codes(BASE + "ENV NODE_ENV=production\n"))

    def test_riferimento_a_variabile_non_e_un_segreto_in_chiaro(self):
        self.assertNotIn("DW031", codes(BASE + "ENV API_TOKEN=$BUILD_TOKEN\n"))

    def test_curl_pipe_shell(self):
        self.assertIn("DW032", codes(BASE + "RUN curl -fsSL https://e.invalid/x.sh | sh\n"))

    def test_chmod_777(self):
        self.assertIn("DW033", codes(BASE + "RUN chmod 777 /app\n"))
        self.assertIn("DW033", codes(BASE + "RUN chmod -R 0777 /app\n"))
        self.assertNotIn("DW033", codes(BASE + "RUN chmod 755 /app\n"))

    def test_sudo(self):
        self.assertIn("DW034", codes(BASE + "RUN sudo apt-get install -y curl\n"))

    def test_add_da_url(self):
        self.assertIn("DW035", codes(BASE + "ADD https://e.invalid/f.txt /f.txt\n"))

    def test_add_di_file_locale(self):
        self.assertIn("DW035", codes(BASE + "ADD config.json /config.json\n"))

    def test_add_di_archivio_e_legittimo(self):
        self.assertNotIn("DW035", codes(BASE + "ADD pacchetto.tar.gz /opt/\n"))


class Runtime(unittest.TestCase):
    def test_cmd_in_forma_shell(self):
        self.assertIn("DW040", codes(BASE + "CMD npm start\n"))

    def test_cmd_in_forma_esec(self):
        self.assertNotIn("DW040", codes(BASE + 'CMD ["node", "server.js"]\n'))

    def test_healthcheck_assente(self):
        self.assertIn("DW041", codes(BASE))

    def test_healthcheck_presente(self):
        self.assertNotIn("DW041", codes(BASE + 'HEALTHCHECK CMD ["node", "hc.js"]\n'))

    def test_cd_invece_di_workdir(self):
        self.assertIn("DW042", codes(BASE + "RUN cd /app\n"))
        self.assertNotIn("DW042", codes(BASE + "RUN cd /app && make\n"))

    def test_porta_non_valida(self):
        self.assertIn("DW043", codes(BASE + "EXPOSE http\n"))
        self.assertIn("DW043", codes(BASE + "EXPOSE 70000\n"))
        self.assertNotIn("DW043", codes(BASE + "EXPOSE 8080/tcp\n"))

    def test_maintainer_deprecato(self):
        self.assertIn("DW044", codes(BASE + "MAINTAINER a@b.invalid\n"))

    def test_errore_di_sintassi_diventa_una_segnalazione(self):
        self.assertIn("DW045", codes("FROM alpine:3.20\nUSER app\nRUNN echo\n"))


class Filtering(unittest.TestCase):
    def test_regola_disattivata(self):
        self.assertNotIn("DW041", codes(BASE, disabled={"DW041"}))

    def test_soppressione_inline(self):
        text = BASE + "RUN apt-get install -y curl  # dockerwarden:ignore=DW010\n"
        found = codes(text)
        self.assertNotIn("DW010", found)
        self.assertIn("DW011", found)

    def test_ordinamento_per_riga(self):
        findings = analyze(parse(BASE + "RUN npm install\nCMD ciao\n"))
        righe = [finding.line for finding in findings]
        self.assertEqual(righe, sorted(righe))


class Registry(unittest.TestCase):
    def test_codici_unici(self):
        codici = [rule.code for rule in all_rules()]
        self.assertEqual(len(codici), len(set(codici)))

    def test_ogni_regola_ha_una_spiegazione(self):
        for rule in all_rules():
            self.assertTrue(rule.title, rule.code)
            self.assertTrue(rule.help_text, rule.code)
            self.assertIn(rule.severity, {"error", "warning", "note"}, rule.code)


if __name__ == "__main__":
    unittest.main()
