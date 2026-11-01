"""Walk a directory tree and find cryptographic usage. Files are only read."""
from __future__ import annotations

import fnmatch
import os

from . import pyctx
from . import rules as R

EXTS = {".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".java", ".kt", ".go", ".rs", ".c", ".h", ".cc", ".cpp", ".hpp",
        ".cs", ".rb", ".php", ".swift", ".m", ".scala", ".sh", ".conf", ".cfg", ".ini", ".yml", ".yaml", ".toml", ".json",
        ".properties", ".xml", ".pem", ".crt", ".cer", ".key", ".tf", ".gradle"}
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", ".tox", ".mypy_cache", "target"}
MAX_BYTES = 1_000_000
WEAK_SIZE = {"RSA": 2048, "Diffie-Hellman / DSA (finite field)": 2048}


def _ignored(rel, patterns):
    rel = rel.replace(os.sep, "/")
    return any(fnmatch.fnmatch(rel, p) or fnmatch.fnmatch(rel, p.rstrip("/") + "/*") for p in patterns)


def iter_files(root, ignore):
    if os.path.isfile(root):
        yield root, os.path.basename(root)
        return
    for dirpath, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not os.path.islink(os.path.join(dirpath, d)))
        for f in sorted(files):
            full = os.path.join(dirpath, f)
            rel = os.path.relpath(full, root)
            if os.path.islink(full) or _ignored(rel, ignore):
                continue
            if os.path.splitext(f)[1].lower() in EXTS:
                yield full, rel


def usage_of(line):
    c = bool(R.CONFIDENTIALITY.search(line))
    a = bool(R.AUTHENTICITY.search(line))
    return "confidentiality" if c and not a else "authenticity" if a and not c else "unknown"


def scan_text(text, rel):
    lines = text.splitlines()
    # Only Python gets a context pass; for every other language confidence stays "normal".
    defs = pyctx.definition_lines(text) if rel.lower().endswith(".py") else {}
    hits = []
    for i, line in enumerate(lines):
        if R.IMPORT_LINE.match(line) and not line.lstrip().startswith("#include <openssl"):
            continue
        for rid, name, prim, status, quantum, rx, note in R.RULES + [R.RNG]:
            if rx.search(line) and not R.COMMENT_START.match(line):
                if rid == "CS-RNG-WEAK" and not R.RNG_CONTEXT.search(line):
                    continue
                if rid == "CS-MODE-ECB" and "ecb" in line.lower() and R.COMMENT_START.match(line):
                    continue
                size, st = None, status
                if name in WEAK_SIZE or rid == "CS-KEX-DH":
                    window = " ".join(lines[i:i + 4])
                    m = R.SIZE_RE.search(window)
                    if m:
                        size = int(next(g for g in m.groups() if g))
                        key = "RSA" if name == "RSA" else "Diffie-Hellman / DSA (finite field)"
                        if size < WEAK_SIZE[key] and size >= 256:
                            st = "weak"
                hits.append({"rule": rid, "algorithm": name, "primitive": prim, "status": st, "quantum": quantum,
                             "file": rel.replace(os.sep, "/"), "line": i + 1, "key_size": size, "usage": usage_of(line), "note": note,
                             "confidence": "low" if (i + 1) in defs else "normal", "context": defs.get(i + 1, "unknown")})
        for rid, rx, label in R.KEY_MATERIAL:
            if rx.search(line):
                hits.append({"rule": rid, "algorithm": label, "primitive": "key" if rid == "CS-KEY-PRIVATE" else "certificate",
                             "status": "broken" if rid == "CS-KEY-PRIVATE" else "ok", "quantum": "n/a", "file": rel.replace(os.sep, "/"),
                             "line": i + 1, "key_size": None, "usage": "unknown", "confidence": "normal", "context": "unknown",
                             "note": "Never printed. Rotate it and remove it from history." if rid == "CS-KEY-PRIVATE" else "Check expiry and algorithm with your certificate tooling."})
    return hits


def scan_tree(root, ignore=()):
    hits, skipped = [], []
    n = 0
    for full, rel in iter_files(root, ignore):
        try:
            if os.path.getsize(full) > MAX_BYTES:
                skipped.append((rel, "larger than 1 MB"))
                continue
            with open(full, "rb") as fh:
                raw = fh.read()
        except OSError as e:
            skipped.append((rel, e.strerror))
            continue
        if b"\0" in raw[:4096]:
            skipped.append((rel, "binary"))
            continue
        n += 1
        hits += scan_text(raw.decode("utf-8", errors="replace"), rel)
    return hits, n, skipped
