import json, os, subprocess, sys, tempfile, unittest

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, os.path.join(ROOT, "src"))
from cryptoscan import priority
from cryptoscan.cli import analyse, load_config
from cryptoscan.output import to_cbom, to_sarif
from cryptoscan.scan import scan_text, scan_tree

PEM = "-----BEGIN " + "RSA PRIVATE KEY-----"          # split so this file is not itself a hit
FAKE_BODY = "MIIEowIBAAKCAQEA" + "Z" * 20


def algs(text):
    return {h["algorithm"] for h in scan_text(text, "f.py")}


class Detect(unittest.TestCase):
    def test_positive_cases(self):
        cases = {
            "hashlib.md5(x)": "MD5", 'MessageDigest.getInstance("SHA-1")': "SHA-1", "crypto.createHash('sha1')": "SHA-1",
            'Cipher.getInstance("DESede/CBC/PKCS5Padding")': "3DES", 'Cipher.getInstance("DES/ECB/NoPadding")': "DES",
            "cipher = ARC4.new(key)": "RC4", "AES.new(k, AES.MODE_ECB)": "ECB mode", "rsa.generate_private_key(65537, 2048)": "RSA",
            "x25519.X25519PrivateKey.generate()": "Elliptic-curve (ECDSA/ECDH/EdDSA)", "ctx.minimum_version = ssl.PROTOCOL_TLSv1": "Obsolete SSL/TLS version",
            "AES-256-GCM": "AES", "hashlib.sha256()": "SHA-2 / SHA-3", "kem = ML-KEM-768": "Post-quantum algorithm (ML-KEM/ML-DSA/SLH-DSA/Kyber/Dilithium/SPHINCS+/Falcon)",
            "token = Math.random()": "Non-cryptographic random number generator near key/secret handling",
        }
        for src, alg in cases.items():
            self.assertIn(alg, algs(src), src)

    def test_negative_cases(self):
        for src in ["# md5 is old", "// uses RSA here", "import hashlib", "from cryptography.hazmat.primitives.asymmetric import rsa",
                    "des_cription = 1", "x = random.random()", "ordinary = 'sha256sum'", "model = 'DESIGN'", "TLSv1.3", "ssl.PROTOCOL_TLSv1_2"]:
            bad = [a for a in algs(src) if a not in ("SHA-2 / SHA-3",)]
            self.assertEqual(bad, [], src)

    def test_rsa_key_size_marks_weak_only_below_2048(self):
        hit = lambda s: [h for h in scan_text(s, "f.py") if h["algorithm"] == "RSA"][0]
        self.assertEqual(hit("rsa.generate_private_key(public_exponent=65537, key_size=1024)")["status"], "weak")
        self.assertEqual(hit("rsa.generate_private_key(public_exponent=65537, key_size=2048)")["status"], "ok")
        self.assertEqual(hit("RSA.generate(4096)")["key_size"], 4096)
        self.assertEqual(hit("key = RSA.generate(\n    1024)")["status"], "weak")

    def test_private_key_flagged_and_never_echoed(self):
        hits = scan_text(f"{PEM}\n{FAKE_BODY}\n", "k.pem")
        self.assertEqual([h["rule"] for h in hits], ["CS-KEY-PRIVATE"])
        self.assertNotIn(FAKE_BODY, json.dumps(hits))

    def test_usage_inference(self):
        h = lambda s: [x for x in scan_text(s, "f") if x["algorithm"] == "RSA"][0]["usage"]
        self.assertEqual(h("rsa_encrypt(data)"), "confidentiality")
        self.assertEqual(h("rsa_sign(data)"), "authenticity")
        self.assertEqual(h("use_rsa()"), "unknown")


class Priority(unittest.TestCase):
    H = {"quantum": "vulnerable", "file": "svc/a.py", "usage": "confidentiality"}

    def test_mosca(self):
        cfg = {"quantum_horizon_years": 12, "migration_years": 4, "paths": [{"glob": "svc/*", "data_lifetime_years": 10}]}
        self.assertEqual(priority.classify(self.H, cfg)[0], "start-now")
        cfg["paths"][0]["data_lifetime_years"] = 8        # 8 + 4 = 12, not > 12
        self.assertEqual(priority.classify(self.H, cfg)[0], "plan")

    def test_unassessed_without_numbers(self):
        self.assertEqual(priority.classify(self.H, {})[0], "unassessed")
        cfg = {"quantum_horizon_years": 12, "migration_years": 4}
        self.assertEqual(priority.classify(self.H, cfg)[0], "unassessed")   # no path lifetime

    def test_non_vulnerable_has_no_priority(self):
        self.assertEqual(priority.classify(dict(self.H, quantum="reduced"), {"quantum_horizon_years": 1, "migration_years": 1})[0], None)

    def test_signature_uses_validity(self):
        h = dict(self.H, usage="authenticity")
        cfg = {"quantum_horizon_years": 10, "migration_years": 4, "signature_validity_years": 7}
        self.assertEqual(priority.classify(h, cfg)[0], "start-now")
        self.assertEqual(priority.classify(h, {"quantum_horizon_years": 10, "migration_years": 4})[0], "unassessed")


class Tree(unittest.TestCase):
    def build(self):
        d = tempfile.mkdtemp()
        def w(rel, data, mode="w"):
            p = os.path.join(d, rel); os.makedirs(os.path.dirname(p), exist_ok=True); open(p, mode).write(data)
        w("src/a.py", "hashlib.md5(x)\n")
        w("node_modules/x/b.js", "md5(x)\n")
        w("tests/t.py", "hashlib.md5(x)\n")
        w("src/blob.py", b"\0\0md5".decode("latin1"))
        w("big.py", "md5\n" * 400_000)
        os.symlink(os.path.join(d, "src/a.py"), os.path.join(d, "link.py"))
        return d

    def test_walk_rules(self):
        d = self.build()
        hits, n, skipped = scan_tree(d, ignore=["tests/*"])
        self.assertEqual({h["file"] for h in hits}, {"src/a.py"})
        reasons = {s[1] for s in skipped}
        self.assertTrue({"binary", "larger than 1 MB"} <= reasons)

    def test_cbom_shape(self):
        d = self.build()
        res = analyse(d, {"ignore": ["tests/*"]})
        c = json.loads(to_cbom(res, "demo"))
        self.assertEqual(c["bomFormat"], "CycloneDX")
        comp = c["components"][0]
        self.assertEqual(comp["type"], "cryptographic-asset")
        self.assertEqual(comp["cryptoProperties"]["assetType"], "algorithm")
        self.assertTrue(comp["evidence"]["occurrences"][0]["location"])

    def test_sarif_shape(self):
        d = self.build()
        res = analyse(d, {"ignore": ["tests/*"]})
        s = json.loads(to_sarif(res))
        self.assertEqual(s["version"], "2.1.0")
        run = s["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "cryptoscan")
        self.assertTrue(run["results"])
        r0 = run["results"][0]
        self.assertIn(r0["level"], {"error", "warning", "note"})
        self.assertTrue(r0["locations"][0]["physicalLocation"]["artifactLocation"]["uri"])
        self.assertIsInstance(r0["locations"][0]["physicalLocation"]["region"]["startLine"], int)
        rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
        self.assertTrue({res["ruleId"] for res in run["results"]} <= rule_ids)


class Cli(unittest.TestCase):
    def run_cli(self, *a, cwd=None):
        env = dict(os.environ, PYTHONPATH=os.path.join(ROOT, "src"))
        return subprocess.run([sys.executable, "-m", "cryptoscan", *a], capture_output=True, text=True, env=env, cwd=cwd)

    def test_exit_codes_and_demo(self):
        demo = os.path.join(ROOT, "examples", "demo-repo")
        self.assertEqual(self.run_cli(demo).returncode, 0)
        self.assertEqual(self.run_cli(demo, "--fail-on", "broken").returncode, 1)
        self.assertEqual(self.run_cli("/nonexistent").returncode, 2)
        out = self.run_cli(demo, "--config", os.path.join(demo, ".cryptoscan.json"), "--format", "json").stdout
        self.assertTrue(any(h.get("priority") == "start-now" for h in json.loads(out)["hits"]))

    def test_sarif_cli_output(self):
        demo = os.path.join(ROOT, "examples", "demo-repo")
        out = self.run_cli(demo, "--format", "sarif").stdout
        sarif = json.loads(out)
        self.assertEqual(sarif["runs"][0]["tool"]["driver"]["name"], "cryptoscan")

    def test_bad_config(self):
        d = tempfile.mkdtemp(); c = os.path.join(d, "c.json"); open(c, "w").write('{"migration_years": -1}')
        self.assertEqual(self.run_cli(d, "--config", c).returncode, 2)
        with self.assertRaises(ValueError):
            load_config(c)


def conf(text, rel="f.py"):
    return {(h["algorithm"], h["line"]): h["confidence"] for h in scan_text(text, rel)}


class Context(unittest.TestCase):
    """Python AST context: declarations are low confidence, real use never is."""

    def test_constant_tables_and_docstrings_are_low(self):
        src = (
            '"""Module notes: md5 and sha1 are discussed here."""\n'
            'LEGACY = ("md5", "sha1")\n'
            'PROTOCOL_NAMES = {\n    PROTOCOL_SSLv3: "SSLv3",\n}\n'
            'MD5 = hashlib.md5\n'
        )
        got = conf(src)
        self.assertTrue(got and all(v == "low" for v in got.values()), got)

    def test_real_use_stays_normal(self):
        cases = [
            "def f(x):\n    return hashlib.md5(x)\n",
            "h = hashlib.md5(b'x')\n",
            "HASH = hashlib.md5\n",                         # alias under a different name: configuration of use
            "class C:\n    def m(self):\n        return hashlib.sha1()\n",
            "ALGO = pick('md5')\n",                          # a call is never a declaration
            "def f():\n    LEGACY = ('md5',)\n    return LEGACY\n",   # inside a function: use
        ]
        for src in cases:
            got = conf(src)
            self.assertTrue(got, src)
            self.assertTrue(all(v == "normal" for v in got.values()), (src, got))

    def test_imports_including_multiline_are_low(self):
        got = conf("from ssl import (\n    PROTOCOL_SSLv3,\n    PROTOCOL_TLSv1,\n)\n")
        self.assertTrue(got and all(v == "low" for v in got.values()), got)

    def test_enum_members_are_low_but_methods_are_not(self):
        src = "class V(IntEnum):\n    SSLv3 = _ssl.PROTO_SSLv3\n    def go(self):\n        return ssl.PROTOCOL_SSLv3\n"
        got = conf(src)
        self.assertEqual(got[("Obsolete SSL/TLS version", 2)], "low")
        self.assertEqual(got[("Obsolete SSL/TLS version", 4)], "normal")

    def test_private_key_in_a_constant_is_never_downgraded(self):
        hits = scan_text(f'KEY = "{PEM}"\n', "f.py")
        self.assertEqual([h["confidence"] for h in hits if h["rule"] == "CS-KEY-PRIVATE"], ["normal"])

    def test_other_languages_and_unparseable_python_stay_normal(self):
        self.assertEqual(set(conf('LEGACY = ["md5"]\n', "x.js").values()), {"normal"})
        self.assertEqual(set(conf('LEGACY = ("md5",\n', "x.py").values()), {"normal"})   # syntax error

    def test_parse_warnings_do_not_leak_to_stderr(self):
        d = tempfile.mkdtemp()
        with open(os.path.join(d, "w.py"), "w") as fh:
            fh.write('import re\nPAT = re.compile("\\d+")\nBAD = "\\d"\nLEGACY = ("md5",)\n')
        env = dict(os.environ, PYTHONPATH=os.path.join(ROOT, "src"))
        p = subprocess.run([sys.executable, "-W", "error", "-m", "cryptoscan", d], capture_output=True, text=True, env=env)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stderr, "")

    def test_cli_min_confidence_filters_and_reports_hidden_count(self):
        d = tempfile.mkdtemp()
        with open(os.path.join(d, "t.py"), "w") as fh:
            fh.write('LEGACY = ("md5", "sha1")\ndef f(x):\n    return hashlib.md5(x)\n')
        env = dict(os.environ, PYTHONPATH=os.path.join(ROOT, "src"))
        run = lambda *a: subprocess.run([sys.executable, "-m", "cryptoscan", d, "--format", "json", *a], capture_output=True, text=True, env=env)
        every, strict = json.loads(run().stdout), json.loads(run("--min-confidence", "normal").stdout)
        self.assertEqual((len(every["hits"]), every["hidden_low_confidence"]), (3, 0))
        self.assertEqual((len(strict["hits"]), strict["hidden_low_confidence"]), (1, 2))
        self.assertEqual(strict["hits"][0]["line"], 3)
        # the gate follows what is shown: the only broken hit left is the real use
        self.assertEqual(run("--min-confidence", "normal", "--fail-on", "broken").returncode, 1)

    def test_text_report_mentions_hidden_and_shown_low_hits(self):
        d = tempfile.mkdtemp()
        with open(os.path.join(d, "t.py"), "w") as fh:
            fh.write('LEGACY = ("md5",)\n')
        env = dict(os.environ, PYTHONPATH=os.path.join(ROOT, "src"))
        shown = subprocess.run([sys.executable, "-m", "cryptoscan", d], capture_output=True, text=True, env=env).stdout
        hidden = subprocess.run([sys.executable, "-m", "cryptoscan", d, "--min-confidence", "normal"], capture_output=True, text=True, env=env).stdout
        self.assertIn("likely not use", shown)
        self.assertIn("hidden by --min-confidence", hidden)


if __name__ == "__main__":
    unittest.main()


def test_cbom_validates_against_official_cyclonedx_16_schema():
    # The CBOM claim is checked, not asserted: validate real output against
    # the vendored official CycloneDX 1.6 JSON schema (tests/bom-1.6.schema.json,
    # Apache-2.0, cyclonedx.org). jsonschema is a test-only dependency; the
    # tool itself stays dependency-free.
    try:
        import jsonschema
    except ImportError:
        raise unittest.SkipTest("jsonschema is a test-only dependency")
    root = os.path.join(ROOT, "examples", "demo-repo")
    doc = json.loads(to_cbom(analyse(root, {}), "demo-repo"))
    schema = json.load(open(os.path.join(os.path.dirname(__file__), "bom-1.6.schema.json"), encoding="utf-8"))
    jsonschema.validate(doc, schema)
