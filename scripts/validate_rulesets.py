#!/usr/bin/env python3
"""Deterministic matcher validation for Surge classical RULE-SET lists.

Validates syntax, cross-list duplicates/shadowing, and representative
positive/negative host cases. Does not claim on-device success.
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
            # Allow "no-resolve" only as third field for IP rules.
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
            # Special-case: DOMAIN,cp4.cloudflare.com is allowed; DOMAIN-SUFFIX,cloudflare.com not.
            errors.append(f"forbidden matcher present: {fname} {atype},{value}")

    # Ensure guzzoni is only in Direct, not AI
    ai_values = parsed["Apple-AI.list"]
    for atype, value, _ in ai_values:
        if "guzzoni" in value:
            errors.append("guzzoni must not remain in Apple-AI.list (moved to Direct)")
        if value in {"mask.icloud.com", "mask-h2.icloud.com", "mask-api.icloud.com"} or (
            atype.startswith("DOMAIN") and value.startswith("mask.") and "icloud" in value
        ):
            errors.append(f"Private Relay host should not be in Apple-AI.list: {atype},{value}")

    # Claude preservation smoke: anthropic + muse still present
    claude_vals = {v for _a, v, _ in parsed["Claude-AI.list"]}
    for must in ("anthropic.com", "claude.ai", "muse.ai"):
        if must not in claude_vals and not any(must in v for v in claude_vals):
            errors.append(f"Claude-AI.list missing expected {must}")

    # Build deterministic ordered chain: Direct then AI then Claude (domain rules only)
    ordered: list[tuple[str, str, str, str | None]] = []
    for fname in ("Apple-Siri-Direct.list", "Apple-AI.list", "Claude-AI.list"):
        for atype, value, opt in parsed[fname]:
            ordered.append((fname, atype, value, opt))

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
        ("gateway.icloud.com", None),
        ("www.cloudflare.com", None),
        ("something.cp4.cloudflare.com", None),  # DOMAIN exact only for cp4
        ("notsiri.example.com", None),
        ("apple.com", None),
    ]

    # Shadow check: hosts that should hit Direct must not be reachable only via AI
    for host, expected in cases:
        hit = first_match(host, ordered)
        got = hit[0] if hit else None
        # For negatives expected None: also ignore Claude accidental hits only if host clearly Claude — none of negatives are.
        if expected is None:
            if got in {"Apple-Siri-Direct.list", "Apple-AI.list"}:
                errors.append(f"negative case {host} unexpectedly matched {got} via {hit}")
        else:
            if got != expected:
                errors.append(f"case {host}: expected {expected}, got {got} ({hit})")

    # Suffix/exact shadowing report within Apple lists (informational hard-fail if Direct suffix
    # would always win over an AI more-specific rule for same tree — currently none expected).
    # Example hard fail: if AI had DOMAIN,api.smoot.apple.com while Direct has SUFFIX smoot.
    for atype, value, _ in parsed["Apple-AI.list"]:
        if atype not in {"DOMAIN", "DOMAIN-SUFFIX"}:
            continue
        # If Direct already matches this host via suffix, AI entry is shadowed when Direct is first.
        probe_host = value if atype == "DOMAIN" else f"probe.{value}"
        # For DOMAIN-SUFFIX value itself as host:
        hosts_to_probe = [value]
        if atype == "DOMAIN-SUFFIX":
            hosts_to_probe.append(f"x.{value}")
        for h in hosts_to_probe:
            hit = first_match(h, ordered)
            if hit and hit[0] == "Apple-Siri-Direct.list" and (atype, value) in ai:
                # Only error if the AI rule is the one that would have matched in isolation
                if domain_matches(h, atype, value):
                    errors.append(
                        f"shadowed AI rule {atype},{value}: host {h} won by Direct {hit[1]},{hit[2]}"
                    )

    if errors:
        # Dedupe while preserving order
        uniq = list(dict.fromkeys(errors))
        print(f"FAIL ({len(uniq)} issues)")
        for e in uniq:
            print(" -", e)
        return 1

    # Summary counts
    print("PASS")
    for name, rules in parsed.items():
        by = defaultdict(int)
        for a, _v, _o in rules:
            by[a] += 1
        print(f"  {name}: {len(rules)} rules {dict(by)}")
    print(f"  cases checked: {len(cases)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
