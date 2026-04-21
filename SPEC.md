name: jwthawk
repo_name: JWTHawk
subtitle: Mint Privileged JWT Variants from a Captured Token
naming_format: 3 — CamelCase + suffix (Hawk)
purpose: Mint a family of privileged/forged JWT variants from a captured token (alg:none, alg confusion, kid SQLi, kid path traversal, jku injection, role escalation, exp extension) and emit a working curl per attack so the user can confirm bypass against the target.
actionable_payoff: Final block prints, per attack, the mutated JWT and a copy-paste curl that replays a captured request with the malicious token substituted in. The user pastes one curl, gets a 200 (or doesn't), reports the bypass with the proof curl in hand.
language: python
why_language: stdlib `base64` + `hmac` + `json` + `argparse` + `urllib` cover JWT mint, curl format, and target-curl substitution. PyJWT is heavier than needed; rolling our own keeps the binary footprint at zero deps.
features:
- Eight attack families: alg:none, empty-sig, alg-confusion (HS256 over RSA pubkey), kid SQLi, kid path traversal, jku/x5u url injection, role escalation (admin/is_admin/is_staff), exp extension
- Diff-style output: original token decoded vs mutated, with `-` and `+` lines per change
- Optional --target-curl with `{TOKEN}` placeholder; tool emits the substituted curl per attack
- Works on both HS256 and RS256 baselines (alg-confusion needs `--pubkey` for the surgical case)
- Pure stdlib, no PyJWT dependency
input_contract: --token (the captured JWT) plus optional --target-curl, --pubkey (for alg-confusion), --hmac-key (for shaping the alg:none control)
output_contract: per-attack diff block (decoded header/payload, +/- lines for each change) followed by the mutated token and a substituted curl ready to run
output_style: diff — `-`/`+` line prefixes with red/green ANSI when tty, no tables, no box-drawing, no `══` rule, no log-tree glyphs. Distinct from curl2nuclei (yaml+box), paramsneak (log-tree+>>), corsbake (`══`+narrative).
safe_test_target: built-in fixture token (`alg:HS256, sub:alice, role:user`) and a fake target curl pointing at httpbin.org/headers
synonym_names:
- TokenHawk
- JWTForge
- 0xJWT
source_inspiration_url: https://portswigger.net/web-security/jwt
