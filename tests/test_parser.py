import unittest

from dockerwarden.parser import parse


class Basics(unittest.TestCase):
    def test_istruzioni_e_righe(self):
        result = parse("FROM alpine:3.20\n# commento\nRUN echo ciao\n")
        self.assertEqual([i.keyword for i in result.instructions], ["FROM", "RUN"])
        self.assertEqual(result.instructions[1].line, 3)

    def test_parola_chiave_case_insensitive(self):
        self.assertEqual(parse("from alpine:3.20\n").instructions[0].keyword, "FROM")

    def test_istruzione_sconosciuta(self):
        result = parse("FROM alpine:3.20\nRUNN echo\n")
        self.assertEqual(len(result.errors), 1)
        self.assertIn("RUNN", result.errors[0][1])

    def test_direttive_iniziali(self):
        result = parse("# syntax=docker/dockerfile:1\n# escape=`\nFROM alpine:3.20\n")
        self.assertEqual(result.directives["syntax"], "docker/dockerfile:1")
        self.assertEqual(result.directives["escape"], "`")

    def test_commento_dopo_la_prima_istruzione_non_e_direttiva(self):
        result = parse("FROM alpine:3.20\n# escape=`\nRUN echo\n")
        self.assertNotIn("escape", result.directives)


class Continuations(unittest.TestCase):
    def test_riga_continuata(self):
        result = parse("FROM alpine:3.20\nRUN apt-get update \\\n && apt-get install -y curl\n")
        self.assertEqual(len(result.instructions), 2)
        self.assertIn("apt-get install", result.instructions[1].value)

    def test_commento_dentro_una_continuazione_viene_scartato(self):
        result = parse("FROM alpine:3.20\nRUN uno \\\n# nota\n && due\n")
        self.assertIn("uno", result.instructions[1].value)
        self.assertIn("due", result.instructions[1].value)
        self.assertNotIn("nota", result.instructions[1].value)

    def test_escape_alternativo(self):
        result = parse("# escape=`\nFROM alpine:3.20\nRUN uno `\n due\n")
        self.assertIn("due", result.instructions[1].value)

    def test_continuazione_senza_seguito(self):
        result = parse("FROM alpine:3.20\nRUN echo \\\n")
        self.assertTrue(any("senza seguito" in message for _, message in result.errors))


class Flags(unittest.TestCase):
    def test_flag_di_copy(self):
        result = parse("FROM alpine:3.20\nCOPY --from=build --chown=node:node /a /b\n")
        copy = result.instructions[1]
        self.assertEqual(copy.flags["from"], "build")
        self.assertEqual(copy.flags["chown"], "node:node")
        self.assertEqual(copy.value, "/a /b")

    def test_flag_senza_valore(self):
        result = parse("FROM alpine:3.20\nRUN --network=none echo\n")
        self.assertEqual(result.instructions[1].flags["network"], "none")


class Heredoc(unittest.TestCase):
    def test_corpo_assorbito_nella_istruzione(self):
        text = "FROM alpine:3.20\nRUN <<EOF\napt-get update\napt-get install -y curl\nEOF\nUSER app\n"
        result = parse(text)
        self.assertEqual([i.keyword for i in result.instructions], ["FROM", "RUN", "USER"])
        self.assertIn("apt-get install", result.instructions[1].value)


class Stages(unittest.TestCase):
    def test_stage_multipli_con_alias(self):
        result = parse("FROM node:22 AS build\nRUN npm ci\nFROM node:22\nCOPY --from=build /a /b\n")
        self.assertEqual(len(result.stages), 2)
        self.assertEqual(result.stages[0].alias, "build")
        self.assertIsNone(result.stages[1].alias)
        self.assertEqual(len(result.stages[0].instructions), 1)

    def test_tag_e_digest(self):
        result = parse("FROM node:22.1@sha256:abc\n")
        stage = result.stages[0]
        self.assertEqual(stage.base_name, "node")
        self.assertEqual(stage.tag, "22.1")
        self.assertTrue(stage.has_digest)

    def test_senza_tag(self):
        self.assertIsNone(parse("FROM node\n").stages[0].tag)

    def test_stage_finale(self):
        result = parse("FROM a:1 AS uno\nFROM b:2 AS due\n")
        self.assertEqual(result.final_stage.alias, "due")


class Suppression(unittest.TestCase):
    def test_soppressione_di_un_codice(self):
        result = parse("FROM alpine:3.20\nRUN apt-get install -y curl  # dockerwarden:ignore=DW010\n")
        run = result.instructions[1]
        self.assertTrue(run.suppresses("DW010"))
        self.assertFalse(run.suppresses("DW011"))

    def test_soppressione_totale(self):
        result = parse("FROM alpine:3.20\nRUN qualcosa  # dockerwarden:ignore\n")
        self.assertTrue(result.instructions[1].suppresses("DW999"))


if __name__ == "__main__":
    unittest.main()
