from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__, output, priority
from .scan import scan_tree


def load_config(path):
    if not path:
        for cand in (".cryptoscan.json",):
            if os.path.isfile(cand):
                path = cand
    if not path:
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            cfg = json.load(fh)
    except (OSError, json.JSONDecodeError) as e:
        raise ValueError(f"config {path}: {getattr(e, 'strerror', None) or e}")
    if not isinstance(cfg, dict):
        raise ValueError(f"config {path}: expected an object")
    for k in ("quantum_horizon_years", "migration_years", "signature_validity_years"):
        if k in cfg and (not isinstance(cfg[k], (int, float)) or cfg[k] < 0):
            raise ValueError(f"config {path}: {k} must be a non-negative number")
    for rule in cfg.get("paths", []):
        if not isinstance(rule, dict) or "glob" not in rule or not isinstance(rule.get("data_lifetime_years", 0), (int, float)):
            raise ValueError(f"config {path}: each paths entry needs a glob and a numeric data_lifetime_years")
    return cfg


def analyse(root, cfg, min_confidence="low"):
    hits, n, skipped = scan_tree(root, cfg.get("ignore", []))
    hidden = 0
    if min_confidence == "normal":
        kept = [h for h in hits if h.get("confidence", "normal") == "normal"]
        hidden, hits = len(hits) - len(kept), kept
    for h in hits:
        p, why = priority.classify(h, cfg)
        if p:
            h["priority"], h["priority_reason"] = p, why
    hits.sort(key=lambda h: (output.ORDER[h["status"]], h["file"], h["line"]))
    res = {"tool": "cryptoscan", "version": __version__, "root": os.path.basename(os.path.abspath(root)), "files_scanned": n,
           "skipped": [{"file": f, "reason": r} for f, r in skipped], "hits": hits,
           "hidden_low_confidence": hidden}
    res["summary"] = output.summarise(hits)
    return res


def main(argv=None):
    p = argparse.ArgumentParser(prog="cryptoscan", description="Inventory cryptography in source code and prioritise quantum migration. Reads files only.")
    p.add_argument("path", help="directory or file to scan")
    p.add_argument("--config", help="JSON config (default: ./.cryptoscan.json if present)")
    p.add_argument("--format", choices=["text", "json", "cbom", "sarif"], default="text")
    p.add_argument("-o", "--output")
    p.add_argument("--min-confidence", choices=["low", "normal"], default="low",
                   help="'normal' hides Python hits that sit in constant definitions or docstrings (likely tables of names, not use). Default 'low' shows everything")
    p.add_argument("--fail-on", choices=["broken", "weak", "never"], default="never")
    p.add_argument("--version", action="version", version=f"cryptoscan {__version__}")
    a = p.parse_args(argv)
    if not os.path.exists(a.path):
        print(f"cryptoscan: {a.path}: no such file or directory", file=sys.stderr)
        return 2
    try:
        cfg = load_config(a.config)
    except ValueError as e:
        print(f"cryptoscan: {e}", file=sys.stderr)
        return 2
    res = analyse(a.path, cfg, a.min_confidence)
    body = (output.to_json(res) if a.format == "json" else
            output.to_cbom(res, res["root"]) if a.format == "cbom" else
            output.to_sarif(res) if a.format == "sarif" else
            output.to_text(res))
    if a.output:
        with open(a.output, "w", encoding="utf-8") as fh:
            fh.write(body)
    else:
        sys.stdout.write(body)
    c = output.counts(res)
    if a.fail_on == "broken" and c["broken"]:
        return 1
    if a.fail_on == "weak" and (c["broken"] or c["weak"]):
        return 1
    return 0
