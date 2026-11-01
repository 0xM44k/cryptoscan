# Changelog

## 0.3.0 — 2026-11
- Python declaration-versus-use pass (`ast`): hits in docstrings, imports, Enum members and UPPER_CASE constant tables are tagged `confidence: low`; new `--min-confidence normal` hides them and reports the count.
- `confidence` and `context` fields added to JSON hits; private keys and certificates are never downgraded.
- Scanning Python files no longer risks leaking `SyntaxWarning` noise to stderr.
- 9 new tests (26 total).

## 0.2.0 — 2026-10
Added `--format sarif`, so findings can go straight into GitHub code scanning or another SARIF viewer.

## 0.1.0 — 2026-10
Initial release. See the README for features and limits.
