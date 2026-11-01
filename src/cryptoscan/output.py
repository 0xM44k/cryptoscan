from __future__ import annotations

import json
from collections import Counter, defaultdict

ORDER = {"broken": 0, "weak": 1, "legacy": 2, "ok": 3, "pqc": 4}


def summarise(hits):
    by_alg = defaultdict(list)
    for h in hits:
        by_alg[h["algorithm"]].append(h)
    rows = []
    for alg, hs in by_alg.items():
        worst = min((h["status"] for h in hs), key=lambda s: ORDER[s])
        rows.append({"algorithm": alg, "status": worst, "quantum": hs[0]["quantum"], "occurrences": len(hs),
                     "files": len({h["file"] for h in hs}), "note": hs[0]["note"]})
    rows.sort(key=lambda r: (ORDER[r["status"]], -r["occurrences"], r["algorithm"]))
    return rows


def to_text(result):
    s = result["summary"]
    out = [f"cryptoscan: {result['files_scanned']} files scanned, {len(result['hits'])} occurrences, {len(s)} distinct algorithms/uses",
           "Textual detection only: expect false positives and misses.", ""]
    for r in s:
        out.append(f"{r['status'].upper():<7} {r['algorithm']}  x{r['occurrences']} in {r['files']} files  [quantum: {r['quantum']}]")
        out.append(f"        {r['note']}")
    pr = [h for h in result["hits"] if h.get("priority") in ("start-now", "plan")]
    if pr:
        out.append("\nQuantum migration priority (from your config)")
        for h in sorted(pr, key=lambda h: (h["priority"] != "start-now", h["file"], h["line"])):
            out.append(f"  {h['priority']:<9} {h['file']}:{h['line']} {h['algorithm']}: {h['priority_reason']}")
    un = [h for h in result["hits"] if h.get("priority") == "unassessed"]
    if un:
        out.append(f"\n{len(un)} quantum-vulnerable occurrences are unassessed: {un[0]['priority_reason']}")
    bad = [h for h in result["hits"] if h["status"] in ("broken", "weak")]
    if bad:
        out.append("\nBroken or weak")
        for h in bad:
            ks = f" ({h['key_size']}-bit)" if h["key_size"] else ""
            out.append(f"  {h['file']}:{h['line']} {h['algorithm']}{ks} [{h['status']}]")
    if result.get("hidden_low_confidence"):
        out.append(f"\n{result['hidden_low_confidence']} hits in Python constant definitions or docstrings were hidden by --min-confidence normal.")
    low = [h for h in result["hits"] if h.get("confidence") == "low"]
    if low:
        out.append(f"{len(low)} shown hits are in Python constant definitions or docstrings (likely not use); rerun with --min-confidence normal to hide them.")
    if result["skipped"]:
        out.append(f"\nSkipped {len(result['skipped'])} files (binary, large or unreadable).")
    return "\n".join(out) + "\n"


def to_cbom(result, name="scanned-project"):
    """CycloneDX CBOM (algorithm assets), CycloneDX 1.6. Validated against the
    official 1.6 JSON schema in the test suite (see docs/RESEARCH.md)."""
    comps, groups = [], defaultdict(list)
    for h in result["hits"]:
        groups[(h["algorithm"], h["primitive"], h["key_size"])].append(h)
    for (alg, prim, size), hs in sorted(groups.items(), key=lambda kv: str(kv[0])):
        ref = "crypto/" + "".join(c.lower() if c.isalnum() else "-" for c in alg).strip("-") + (f"-{size}" if size else "")
        props = {"assetType": "algorithm", "algorithmProperties": {"primitive": prim}}
        if size:
            props["algorithmProperties"]["parameterSetIdentifier"] = str(size)
        comps.append({"type": "cryptographic-asset", "bom-ref": ref, "name": alg + (f"-{size}" if size else ""), "cryptoProperties": props,
                      "evidence": {"occurrences": [{"location": h["file"], "line": h["line"]} for h in hs]},
                      "properties": [{"name": "cryptoscan:status", "value": min((h["status"] for h in hs), key=lambda s: ORDER[s])},
                                     {"name": "cryptoscan:quantum", "value": hs[0]["quantum"]}]})
    return json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
                       "metadata": {"component": {"type": "application", "name": name}, "tools": {"components": [{"type": "application", "name": "cryptoscan", "version": result["version"]}]}},
                       "components": comps}, indent=2)


def to_json(result):
    return json.dumps(result, indent=2)


SARIF_LEVEL = {"broken": "error", "weak": "warning", "legacy": "note", "ok": "note", "pqc": "note"}


def to_sarif(result):
    """SARIF 2.1.0, for GitHub code scanning and similar dashboards. One result per hit."""
    rules, seen, results = [], set(), []
    for h in result["hits"]:
        if h["rule"] not in seen:
            seen.add(h["rule"])
            rules.append({"id": h["rule"], "name": h["algorithm"], "shortDescription": {"text": h["algorithm"]},
                          "fullDescription": {"text": h["note"]},
                          "defaultConfiguration": {"level": SARIF_LEVEL.get(h["status"], "note")}})
        results.append({"ruleId": h["rule"], "level": SARIF_LEVEL.get(h["status"], "note"),
                        "message": {"text": f"{h['algorithm']} ({h['status']}, quantum: {h['quantum']}). {h['note']}"},
                        "locations": [{"physicalLocation": {"artifactLocation": {"uri": h["file"]},
                                                             "region": {"startLine": h["line"]}}}]})
    return json.dumps({"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
                       "runs": [{"tool": {"driver": {"name": "cryptoscan", "version": result["version"], "rules": rules}},
                                "results": results}]}, indent=2)


def counts(result):
    return Counter(h["status"] for h in result["hits"])
