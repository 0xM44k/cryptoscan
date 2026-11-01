# Research record (2026-10-26)

Method: web searches plus page fetches. Search result pages gave titles only; claims below come from fetched pages. In the 2026-10-28 pass the CycloneDX 1.6 documentation and the official JSON schema were fetched; the schema is vendored at tests/bom-1.6.schema.json and the CBOM output is validated against it in the test suite.

## Observed

- Search surfaced several existing CBOM and PQC-discovery tools (for example a PyPI package "quantumshield-pqc", a .NET CBOM CLI, and a vendor code-scanning feature). My fetch of one of them failed, so I do not know what they detect or how they prioritise. This area is crowded; cryptoscan makes no claim to be first.
- [Wikipedia, Cryptographic bill of materials](https://en.wikipedia.org/wiki/Cryptographic_bill_of_materials) (fetched): a CycloneDX CBOM entry is a component with `"type": "cryptographic-asset"`, a `bom-ref` and `cryptoProperties`, with `assetType` (example values `algorithm`, `certificate`) and `algorithmProperties` (`primitive`, `mode`, `parameterSetIdentifier`, `cryptoFunctions`). The page does not list the full enumeration of primitives. cryptoscan uses `algorithm` assets only, with `primitive` values I took from memory (`hash`, `block-cipher`, `pke`, `kem`, ...), plus `evidence.occurrences`, also from memory.
- [postquantum.com on NIST IR 8547](https://postquantum.com/security-pqc/nist-ir-8547-ipd/) (fetched, 2026-10-26): IR 8547 is still an **initial public draft**. It proposes deprecating roughly 112-bit-strength RSA and ECC (for example RSA-2048) after 2030, and disallowing the remaining quantum-vulnerable RSA/ECC by 2035. The page gives no DH dates.
- [postquantum.com on Mosca's theorem](https://postquantum.com/post-quantum/moscas-theorem/) (fetched): X + Y > Q, where X is how long the data must stay secret, Y the time to migrate, Q the time until quantum attackers break current encryption. Q is a forecast. The page notes the inequality is a simplified heuristic and does not model data already being collected.

## Gap targeted and design

Most inventory output is a flat list. Teams need to know *which* quantum-vulnerable uses to migrate first, and that depends on facts only they know: how long the data in that service must stay secret and how long migration will take. cryptoscan lets you state those per path in `.cryptoscan.json` and applies Mosca's inequality, labelling each occurrence `start-now`, `plan` or `unassessed`. It deliberately ships **no default for Q**: choosing it is your judgement, and a default would look like a prediction.

Signatures are treated differently (the exposure is forged signatures after a break, bounded by signature validity, not stored ciphertext), using a usage heuristic from nearby words (sign/verify vs encrypt/key exchange). The heuristic is weak and falls back to treating unknown usage as confidentiality, which errs toward earlier migration.

## Sanity check run

I ran it on Python's own `ssl.py` and `hashlib.py`. It flagged 15 "obsolete SSL/TLS" occurrences in `ssl.py`: those are the library *defining* legacy constants, not using them. This is the main false-positive class: the tool cannot distinguish defining or listing an algorithm from using it.

## Not verified

- Detection precision and recall on real codebases: only the fixtures I wrote and these two stdlib files were used.
- Algorithm status judgements (broken/weak/legacy) are my summary of widely held positions, not a citation per algorithm.
- Languages are matched textually; there is no parsing, so indirect use (algorithm names from config or constants) is missed.
