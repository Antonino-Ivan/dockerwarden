import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from dockerwarden.cli import EXIT_FINDINGS, EXIT_OK, EXIT_USAGE, main

PROBLEMATICO = """FROM node:latest
ENV API_TOKEN=abc123def456
RUN apt-get update
RUN apt-get install -y curl
COPY . .
RUN npm install
CMD npm start
"""

PULITO = """FROM node:22.12.0-slim@sha256:abc
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build
USER node
HEALTHCHECK CMD ["node", "hc.js"]
CMD ["node", "server.js"]
"""


class CliCase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        open(os.path.join(self.dir.name, ".dockerignore"), "w").close()

    def write(self, content, name="Dockerfile"):
        path = os.path.join(self.dir.name, name)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)
        return path

    def run_cli(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main(argv)
        return code, out.getvalue(), err.getvalue()


class Lint(CliCase):
    def test_file_pulito_esce_con_zero(self):
        code, out, _ = self.run_cli(["lint", self.write(PULITO)])
        self.assertEqual(code, EXIT_OK, out)
        self.assertIn("nessun problema", out)

    def test_file_problematico_esce_con_uno(self):
        code, out, _ = self.run_cli(["lint", self.write(PROBLEMATICO)])
        self.assertEqual(code, EXIT_FINDINGS)
        self.assertIn("DW031", out)

    def test_formato_json(self):
        _, out, _ = self.run_cli(["lint", self.write(PROBLEMATICO), "-f", "json"])
        payload = json.loads(out)
        self.assertFalse(payload["ok"])
        self.assertGreater(payload["counts"]["error"], 0)
        self.assertEqual(len(payload["findings"]), sum(payload["counts"].values()))

    def test_formato_sarif_e_valido(self):
        _, out, _ = self.run_cli(["lint", self.write(PROBLEMATICO), "-f", "sarif"])
        document = json.loads(out)
        self.assertEqual(document["version"], "2.1.0")
        run = document["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "dockerwarden")
        self.assertGreater(len(run["tool"]["driver"]["rules"]), 10)
        for result in run["results"]:
            self.assertIn(result["level"], {"error", "warning", "note", "none"})
            region = result["locations"][0]["physicalLocation"]["region"]
            self.assertGreaterEqual(region["startLine"], 1)
            self.assertGreaterEqual(region["endLine"], region["startLine"])

    def test_ogni_risultato_sarif_ha_una_regola_dichiarata(self):
        _, out, _ = self.run_cli(["lint", self.write(PROBLEMATICO), "-f", "sarif"])
        run = json.loads(out)["runs"][0]
        dichiarate = {rule["id"] for rule in run["tool"]["driver"]["rules"]}
        for result in run["results"]:
            self.assertIn(result["ruleId"], dichiarate)

    def test_formato_github(self):
        _, out, _ = self.run_cli(["lint", self.write(PROBLEMATICO), "-f", "github"])
        self.assertTrue(out.startswith("::"))
        self.assertIn("line=", out)

    def test_min_severity(self):
        _, out, _ = self.run_cli(["lint", self.write(PROBLEMATICO), "--min-severity", "error", "-f", "json"])
        payload = json.loads(out)
        self.assertEqual(payload["counts"]["warning"], 0)
        self.assertEqual(payload["counts"]["note"], 0)

    def test_fail_on_warning(self):
        path = self.write(PULITO.replace("RUN npm ci", "RUN npm install"))
        code, _, _ = self.run_cli(["lint", path, "--fail-on", "warning"])
        self.assertEqual(code, EXIT_FINDINGS)

    def test_disable(self):
        _, out, _ = self.run_cli(["lint", self.write(PROBLEMATICO), "--disable", "DW031", "-f", "json"])
        codici = {finding["code"] for finding in json.loads(out)["findings"]}
        self.assertNotIn("DW031", codici)

    def test_disable_con_codice_inesistente(self):
        code, _, err = self.run_cli(["lint", self.write(PULITO), "--disable", "DW999"])
        self.assertEqual(code, EXIT_USAGE)
        self.assertIn("inesistenti", err)

    def test_file_mancante(self):
        code, _, err = self.run_cli(["lint", os.path.join(self.dir.name, "Assente")])
        self.assertEqual(code, EXIT_USAGE)
        self.assertIn("non leggibile", err)

    def test_explain_aggiunge_la_spiegazione(self):
        _, senza, _ = self.run_cli(["lint", self.write(PROBLEMATICO)])
        _, con, _ = self.run_cli(["lint", self.write(PROBLEMATICO), "--explain"])
        self.assertGreater(len(con), len(senza))


class Rules(CliCase):
    def test_elenco_regole(self):
        code, out, _ = self.run_cli(["rules"])
        self.assertEqual(code, EXIT_OK)
        self.assertIn("DW001", out)
        self.assertIn("regole", out)

    def test_elenco_verboso(self):
        _, breve, _ = self.run_cli(["rules"])
        _, lungo, _ = self.run_cli(["rules", "-v"])
        self.assertGreater(len(lungo), len(breve))


if __name__ == "__main__":
    unittest.main()
