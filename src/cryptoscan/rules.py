"""Detection rules. Each rule is a case-insensitive regex over one source line.

status: broken | weak | legacy | ok | pqc
quantum: vulnerable (Shor) | reduced (Grover) | safe | n/a
Detection is textual and approximate: expect false positives (names in
comments, strings, variable names) and false negatives (indirect use).
"""
from __future__ import annotations

import re

def R(p):
    """Compile case-insensitively; \\b becomes a letters-only boundary so snake_case names (use_rsa, rsa_sign) match."""
    p = re.sub(r"(^|\||\()\\b", r"\1(?<![a-z])", p)
    p = p.replace("\\b", "(?![a-z])")
    return re.compile(p, re.I)

RULES = [
    # id, algorithm, primitive, status, quantum, regex, note
    ("CS-HASH-MD5", "MD5", "hash", "broken", "reduced", R(r"\bmd5\b|\bmd5[_(.]|[\"']md5[\"']"), "Collisions are practical. Acceptable only for non-security checksums."),
    ("CS-HASH-SHA1", "SHA-1", "hash", "weak", "reduced", R(r"\bsha-?1\b(?!\d)|[\"']sha-?1[\"']"), "Chosen-prefix collisions are practical; do not use for signatures or integrity against an attacker."),
    ("CS-CIPHER-DES", "DES", "block-cipher", "broken", "reduced", R(r"(?<![a-z0-9_])des(?![a-z0-9_])(?!ede)(?!-ede)|\bdes-cbc\b|\bdes_(ecb|cbc|encrypt|set_key|crypt)\b"), "56-bit key; brute-forceable."),
    ("CS-CIPHER-3DES", "3DES", "block-cipher", "legacy", "reduced", R(r"\b3des\b|tripledes|desede|des-ede3|des_ede3"), "64-bit blocks make Sweet32 attacks feasible on long sessions."),
    ("CS-CIPHER-RC4", "RC4", "stream-cipher", "broken", "reduced", R(r"\brc4\b|\barc4\b|\barcfour\b"), "Biased keystream; prohibited in TLS."),
    ("CS-MODE-ECB", "ECB mode", "block-cipher", "weak", "n/a", R(r"\becb\b|/ecb/|aes_ecb|mode_ecb"), "Identical blocks encrypt identically and leak structure."),
    ("CS-PKE-RSA", "RSA", "pke", "ok", "vulnerable", R(r"\brsa\b|rsa/|rsaes|rsassa|rsa(public|private)?key|[\"']rsa[\"']"), "Broken by Shor's algorithm on a large quantum computer. Key size below 2048 is also weak classically."),
    ("CS-KEX-ECC", "Elliptic-curve (ECDSA/ECDH/EdDSA)", "key-agree", "ok", "vulnerable", R(r"\becdsa\b|\becdh\b|\bed25519\b|\bed448\b|\bx25519\b|\bx448\b|secp\d{3}[rk]1|prime256v1|\bp-?(256|384|521)\b|curve25519|brainpool"), "Broken by Shor's algorithm on a large quantum computer."),
    ("CS-KEX-ECC-WEAK", "Elliptic curve under 224 bits", "key-agree", "weak", "vulnerable", R(r"secp1(28|60|92)[rk]1|\bp-?192\b|prime192v1"), "Below modern classical strength."),
    ("CS-KEX-DH", "Diffie-Hellman / DSA (finite field)", "key-agree", "ok", "vulnerable", R(r"diffie[-_ ]?hellman|\bdhe\b|\bffdhe|\bDH_|\bdsa\b|\bdh\.(generate|params)"), "Broken by Shor's algorithm. Parameters under 2048 bits are weak classically."),
    ("CS-PROTO-OLD-TLS", "Obsolete SSL/TLS version", "protocol", "broken", "n/a", R(r"sslv?[23]\b|\btlsv?1(\.0|_0)?\b(?![._]?[23])|tlsv1[._]1|tls ?1\.[01]\b|protocol_tlsv1(?![._]?[23])|protocol_sslv"), "TLS 1.0/1.1 and SSL are deprecated."),
    ("CS-SYM-AES", "AES", "block-cipher", "ok", "reduced", R(r"\baes[-_]?(128|192|256)?\b|aes[-_]?(gcm|cbc|ctr)"), "Sound. Grover's algorithm halves effective key strength, so AES-256 is the conservative choice for long-lived data."),
    ("CS-SYM-CHACHA", "ChaCha20-Poly1305", "ae", "ok", "reduced", R(r"chacha20"), "Sound."),
    ("CS-HASH-SHA2", "SHA-2 / SHA-3", "hash", "ok", "reduced", R(r"\bsha-?(224|256|384|512)\b|\bsha3[-_]?(224|256|384|512)\b|\bsha2\b"), "Sound."),
    ("CS-KDF", "Password/key derivation (PBKDF2/scrypt/argon2/bcrypt)", "kdf", "ok", "reduced", R(r"pbkdf2|\bscrypt\b|argon2|\bbcrypt\b|\bhkdf\b"), "Sound if parameters are current; this tool does not judge cost factors."),
    ("CS-PQC", "Post-quantum algorithm (ML-KEM/ML-DSA/SLH-DSA/Kyber/Dilithium/SPHINCS+/Falcon)", "kem", "pqc", "safe", R(r"ml-?kem|ml-?dsa|slh-?dsa|\bkyber\b|dilithium|sphincs\+?|\bfalcon\b|fn-?dsa|x25519mlkem|x25519kyber"), "Post-quantum or hybrid construction."),
]

RNG = ("CS-RNG-WEAK", "Non-cryptographic random number generator near key/secret handling", "drbg", "weak", "n/a",
       R(r"math\.random\(|\brandom\.(random|randint|choice|randrange)\(|\brand\(\)|\bmt_rand\(|\bjava\.util\.random\b|\bnew random\("),
       "General-purpose generators are predictable. Use the platform's CSPRNG for keys, tokens and nonces.")
RNG_CONTEXT = R(r"key|secret|token|nonce|\biv\b|salt|password|session|otp")

KEY_MATERIAL = [
    ("CS-KEY-PRIVATE", R(r"-----BEGIN (RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"), "Private key committed to the repository"),
    ("CS-CERT", R(r"-----BEGIN CERTIFICATE-----"), "Certificate in the repository (inventoried, not parsed)"),
]

SIZE_RE = R(r"(?:key_?size|key_?length|bits|modulus_?length|keysize)\D{0,4}(\d{3,5})|generate(?:_private_key|key)?\(\D{0,40}?(\d{3,5})\)|(?:rsa|dh|dsa)[-_ ]?(\d{3,5})\b|initialize\((\d{3,5})")
COMMENT_START = re.compile(r"^\s*(#|//|/\*|\*|--|;|<!--)")
IMPORT_LINE = re.compile(r"^\s*(import|from|using|use|#include|require|package)\b")
CONFIDENTIALITY = R(r"encrypt|decrypt|wrap|unwrap|key[_ ]?(exchange|agree|encapsulat)|ecdh|\bdh\b|diffie|oaep|kem|tls|ssl|cipher|handshake")
AUTHENTICITY = R(r"\bsign|verify|signature|certificate|x509|jwt|jws|firmware|attest")
