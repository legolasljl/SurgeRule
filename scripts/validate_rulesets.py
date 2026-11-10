#!/usr/bin/env python3
"""Deterministic matcher validation for Surge classical RULE-SET lists.

Validates syntax, cross-list duplicates/shadowing, representative
positive/negative host cases, and README-documented combined ordering
(Direct → AI proxy → Claude → broad apple.com catch-all).
Does not claim on-device success.
"""

from __future__ import annotations

import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LIST_FILES = [
    ROOT / "Apple-Siri-Direct.list",
    ROOT / "Apple-AI.list",
    ROOT / "Claude-AI.list",
]

ALLOWED_TYPES = {
    "DOMAIN",
    "DOMAIN-SUFFIX",
    "DOMAIN-KEYWORD",
    "IP-CIDR",
    "IP-CIDR6",
    "IP-ASN",
    "PROCESS-NAME",
    "USER-AGENT",
    "URL-REGEX",
}

RULE_RE = re.compile(
    r"^(?P<atype>DOMAIN|DOMAIN-SUFFIX|DOMAIN-KEYWORD|IP-CIDR6?|IP-ASN|PROCESS-NAME|USER-AGENT|URL-REGEX),"
    r"(?P<value>[^,]+?)(?:,(?P<opt>no-resolve))?$"
)

# Synthetic local catch-all used only in combined-order tests (not shipped in lists).
BROAD_APPLE_DIRECT = ("local-catchall", "DOMAIN-SUFFIX", "apple.com", None)


def parse_list(path: Path) -> list[tuple[str, str, str | None]]:
    rules: list[tuple[str, str, str | None]] = []
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # Forbid embedded policies (third comma field that is not no-resolve / options-only).
        parts = [p.strip() for p in line.split(",")]
        if len(parts) >= 3 and parts[2] not in {"no-resolve"} and not parts[2].startswith(
            ("no-resolve", "extended-matching")
        ):
            if parts[2] not in {"no-resolve"}:
                raise AssertionError(
                    f"{path.name}:{lineno}: policy-like third field forbidden: {line!r}"
                )
        m = RULE_RE.match(line)
        if not m:
            raise AssertionError(f"{path.name}:{lineno}: invalid syntax: {line!r}")
        atype, value, opt = m.group("atype"), m.group("value"), m.group("opt")
        if atype not in ALLOWED_TYPES:
            raise AssertionError(f"{path.name}:{lineno}: unknown type {atype}")
        if atype.startswith("DOMAIN") and (value != value.lower() or " " in value):
            raise AssertionError(f"{path.name}:{lineno}: domain must be lower-case, no spaces")
        rules.append((atype, value, opt))
    return rules


def domain_matches(host: str, atype: str, value: str) -> bool:
    host = host.lower().rstrip(".")
    value = value.lower()
    if atype == "DOMAIN":
        return host == value
    if atype == "DOMAIN-SUFFIX":
        return host == value or host.endswith("." + value)
    if atype == "DOMAIN-KEYWORD":
        return value in host
    return False


def first_match(
    host: str, ordered: list[tuple[str, str, str, str | None]]
) -> tuple[str, str, str] | None:
    """ordered: (list_name, atype, value, opt)"""
    for list_name, atype, value, _opt in ordered:
        if atype.startswith("DOMAIN") and domain_matches(host, atype, value):
            return list_name, atype, value
    return None


def expand_lists(
    parsed: dict[str, list[tuple[str, str, str | None]]], names: list[str]
) -> list[tuple[str, str, str, str | None]]:
    ordered: list[tuple[str, str, str, str | None]] = []
    for fname in names:
        for atype, value, opt in parsed[fname]:
            ordered.append((fname, atype, value, opt))
    return ordered


def main() -> int:
    errors: list[str] = []
    parsed: dict[str, list[tuple[str, str, str | None]]] = {}

    for path in LIST_FILES:
        if not path.exists():
            errors.append(f"missing file: {path}")
            continue
        try:
            parsed[path.name] = parse_list(path)
        except AssertionError as exc:
            errors.append(str(exc))

    if errors:
        print("FAIL: parse")
        for e in errors:
            print(" -", e)
        return 1

    # No policy names / DIRECT / PROXY literals in matcher values beyond domains.
    for name, rules in parsed.items():
        for atype, value, _opt in rules:
            if value.upper() in {"DIRECT", "PROXY", "REJECT"} and atype == "DOMAIN":
                errors.append(f"{name}: suspicious policy-as-domain {value}")

    # Intra-list exact duplicates
    for name, rules in parsed.items():
        seen: dict[tuple[str, str], int] = {}
        for atype, value, _opt in rules:
            key = (atype, value)
            if key in seen:
                errors.append(f"{name}: duplicate {atype},{value}")
            seen[key] = 1

    # Cross Apple-list exact overlaps (same type+value in both Direct and AI)
    direct = {(a, v) for a, v, _ in parsed["Apple-Siri-Direct.list"]}
    ai = {(a, v) for a, v, _ in parsed["Apple-AI.list"]}
    overlap = direct & ai
    if overlap:
        for a, v in sorted(overlap):
            errors.append(f"cross-list exact overlap: {a},{v}")

    # Forbidden over-broad matchers in Apple lists
    forbidden_substrings = [
        ("Apple-AI.list", "DOMAIN-SUFFIX", "cloudflare.com"),  # bare CF — cp4 exact DOMAIN ok
        ("Apple-AI.list", "DOMAIN-SUFFIX", "ls.apple.com"),
        ("Apple-AI.list", "DOMAIN-KEYWORD", "siri"),
        ("Apple-AI.list", "DOMAIN-SUFFIX", "apps.mzstatic.com"),
        ("Apple-AI.list", "DOMAIN-SUFFIX", "mzstatic.com"),
        ("Apple-AI.list", "DOMAIN-SUFFIX", "apple.com"),  # whole Apple catch-all forbidden here
        ("Apple-Siri-Direct.list", "DOMAIN-KEYWORD", "siri"),
    ]
    for fname, atype, value in forbidden_substrings:
        if (atype, value) in {(a, v) for a, v, _ in parsed[fname]}:
            errors.append(f"forbidden matcher present: {fname} {atype},{value}")

    # Ensure guzzoni is only in Direct, not AI; Private Relay apex hosts stay out of AI
    private_relay_forbidden = {
        "mask.icloud.com",
        "mask-h2.icloud.com",
        "mask-api.icloud.com",
        "mask.apple-dns.net",
        "mask-t.apple-dns.net",
        "mask-api.fe.apple-dns.net",
        "mask-api.fe2.apple-dns.net",
    }
    ai_values = parsed["Apple-AI.list"]
    for atype, value, _ in ai_values:
        if "guzzoni" in value:
            errors.append("guzzoni must not remain in Apple-AI.list (moved to Direct)")
        if value in private_relay_forbidden:
            errors.append(f"Private Relay host should not be in Apple-AI.list: {atype},{value}")

    # Required restored community AI-relay aliases (independent recheck)
    ai_pairs = {(a, v) for a, v, _ in ai_values}
    for required in (
        ("DOMAIN-SUFFIX", "apple-relay.mask.apple-dns.net"),
        ("DOMAIN-SUFFIX", "apple-carry-relay.cloudflare.com"),
    ):
        if required not in ai_pairs:
            errors.append(f"Apple-AI.list missing restored matcher {required[0]},{required[1]}")

    # Claude preservation smoke: anthropic + muse still present
    claude_vals = {v for _a, v, _ in parsed["Claude-AI.list"]}
    for must in ("anthropic.com", "claude.ai", "muse.ai"):
        if must not in claude_vals and not any(must in v for v in claude_vals):
            errors.append(f"Claude-AI.list missing expected {must}")

    # README must not recommend catch-alls between Direct and Apple-AI
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    if "Your other Apple / China / system catch-alls go here if you use them" in readme:
        errors.append("README still inserts catch-alls between Direct and Apple-AI")
    if "force `guzzoni` / `smoot` to a proxy **after** these RULE-SETs" in readme:
        errors.append("README migration still says check AFTER (should be BEFORE)")
    for needle in (
        "Apple-Siri-Direct",
        "BEFORE any Apple.com catch-all",
        "before** these RULE-SETs",
        "broad Apple / China / GEOIP",
    ):
        if needle.lower() not in readme.lower() and needle not in readme:
            # soft: ensure key order phrases exist
            pass
    if "BEFORE any Apple.com catch-all" not in readme:
        errors.append("README missing explicit BEFORE any Apple.com catch-all guidance")
    if "earlier rules win" not in readme.lower() and "Earlier rules win" not in readme:
        if "earlier rules win" not in readme:
            errors.append("README should state earlier rules win for migration checks")

    # Build deterministic ordered chain: Direct then AI then Claude (domain rules only)
    ordered = expand_lists(
        parsed, ["Apple-Siri-Direct.list", "Apple-AI.list", "Claude-AI.list"]
    )

    # Positive / negative cases: host -> expected winning list (or None)
    cases: list[tuple[str, str | None]] = [
        # Direct positives
        ("guzzoni.apple.com", "Apple-Siri-Direct.list"),
        ("foo.guzzoni.apple.com", "Apple-Siri-Direct.list"),
        ("api.smoot.apple.com", "Apple-Siri-Direct.list"),
        ("seed.siri.apple.com", "Apple-Siri-Direct.list"),
        ("api-siri-prod.apple.com", "Apple-Siri-Direct.list"),
        ("dejavu.apple.com", "Apple-Siri-Direct.list"),
        ("sequoia.apple.com", "Apple-Siri-Direct.list"),
        # AI / proxy positives
        ("apple-relay.cloudflare.com", "Apple-AI.list"),
        ("x.apple-relay.fastly-edge.com", "Apple-AI.list"),
        ("cp4.cloudflare.com", "Apple-AI.list"),
        ("apple-relay.apple.com", "Apple-AI.list"),
        ("apple-relay.mask.apple-dns.net", "Apple-AI.list"),
        ("staging.apple-carry-relay.cloudflare.com", "Apple-AI.list"),
        ("gspe1-ssl.ls.apple.com", "Apple-AI.list"),
        ("apple-relay.akamaized.net", "Apple-AI.list"),
        ("api.openai.com", "Apple-AI.list"),
        ("chatgpt.com", "Apple-AI.list"),
        # Claude positives
        ("api.anthropic.com", "Claude-AI.list"),
        ("muse.ai", "Claude-AI.list"),
        # Negatives — must NOT be claimed by Apple lists
        ("gspe19-cn-ssl.ls.apple.com", None),  # Maps-ish; not gspe1 exact / not Direct
        ("maps.apple.com", None),
        ("apps.mzstatic.com", None),
        ("mask.icloud.com", None),
        ("mask-api.icloud.com", None),
        ("mask.apple-dns.net", None),  # Private Relay DNS alias — not AI list
        ("gateway.icloud.com", None),
        ("www.cloudflare.com", None),
        ("something.cp4.cloudflare.com", None),  # DOMAIN exact only for cp4
        ("notsiri.example.com", None),
        ("apple.com", None),
    ]

    for host, expected in cases:
        hit = first_match(host, ordered)
        got = hit[0] if hit else None
        if expected is None:
            if got in {"Apple-Siri-Direct.list", "Apple-AI.list"}:
                errors.append(f"negative case {host} unexpectedly matched {got} via {hit}")
        else:
            if got != expected:
                errors.append(f"case {host}: expected {expected}, got {got} ({hit})")

    # Suffix/exact shadowing: Direct must not steal AI hosts when ordered correctly
    for atype, value, _ in parsed["Apple-AI.list"]:
        if atype not in {"DOMAIN", "DOMAIN-SUFFIX"}:
            continue
        hosts_to_probe = [value]
        if atype == "DOMAIN-SUFFIX":
            hosts_to_probe.append(f"x.{value}")
        for h in hosts_to_probe:
            hit = first_match(h, ordered)
            if hit and hit[0] == "Apple-Siri-Direct.list" and (atype, value) in ai:
                if domain_matches(h, atype, value):
                    errors.append(
                        f"shadowed AI rule {atype},{value}: host {h} won by Direct {hit[1]},{hit[2]}"
                    )

    # Combined example order: Direct → AI → Claude → DOMAIN-SUFFIX,apple.com,DIRECT
    combined_correct = ordered + [BROAD_APPLE_DIRECT]
    proxy_must_win = [
        "gspe1-ssl.ls.apple.com",
        "apple-relay.apple.com",
        "apple-relay.cloudflare.com",
        "apple-relay.mask.apple-dns.net",
        "staging.apple-carry-relay.cloudflare.com",
        "cp4.cloudflare.com",
    ]
    for host in proxy_must_win:
        hit = first_match(host, combined_correct)
        if not hit or hit[0] != "Apple-AI.list":
            errors.append(
                f"combined correct order: {host} should win Apple-AI.list, got {hit}"
            )

    # Direct hosts still Direct even with broad apple.com after AI
    for host in ("guzzoni.apple.com", "api.smoot.apple.com", "dejavu.apple.com"):
        hit = first_match(host, combined_correct)
        if not hit or hit[0] != "Apple-Siri-Direct.list":
            errors.append(
                f"combined correct order: {host} should win Direct, got {hit}"
            )

    # Generic apple.com host falls through to catch-all only after AI
    hit = first_match("maps.apple.com", combined_correct)
    if not hit or hit[0] != "local-catchall":
        errors.append(f"combined correct order: maps.apple.com should hit catch-all, got {hit}")

    # Wrong order RELEASE BLOCKER simulation: Direct → broad apple.com → AI
    # (catch-all steals gspe1 / apple-relay.apple.com from proxy)
    wrong = (
        expand_lists(parsed, ["Apple-Siri-Direct.list"])
        + [BROAD_APPLE_DIRECT]
        + expand_lists(parsed, ["Apple-AI.list", "Claude-AI.list"])
    )
    stolen = []
    for host in ("gspe1-ssl.ls.apple.com", "apple-relay.apple.com"):
        hit = first_match(host, wrong)
        if hit and hit[0] == "local-catchall":
            stolen.append(host)
        else:
            errors.append(
                f"wrong-order fixture expected steal of {host} by apple.com catch-all, got {hit}"
            )
    if len(stolen) != 2:
        errors.append("wrong-order fixture did not demonstrate catch-all steal for both hosts")

    # README order prose sanity: Apple-AI example line must appear before catch-all comment block
    # Find first RULE-SET Apple-AI then ensure next catch-all example is after it conceptually —
    # already covered by string checks above.

    if errors:
        uniq = list(dict.fromkeys(errors))
        print(f"FAIL ({len(uniq)} issues)")
        for e in uniq:
            print(" -", e)
        return 1

    print("PASS")
    for name, rules in parsed.items():
        by = defaultdict(int)
        for a, _v, _o in rules:
            by[a] += 1
        print(f"  {name}: {len(rules)} rules {dict(by)}")
    print(f"  cases checked: {len(cases)}")
    print(
        "  combined-order: Direct→AI→Claude→DOMAIN-SUFFIX,apple.com "
        f"proxy-wins={len(proxy_must_win)} wrong-order-steal-ok={len(stolen)}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
