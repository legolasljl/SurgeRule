# SurgeRule

Surge / Clash classical rule lists for external `RULE-SET` / `rule-providers` references.

List files contain **matchers and comments only** — **no policy / proxy-group names**. Bind a policy in your local config. These lists cannot set `[General]` options (`always-real-ip`, `skip-proxy`), cannot disable MitM modules, and cannot rewrite iRingo modules.

Default branch for raw URLs: `main`.

## Rule order (required)

Surge matches **top-down; earlier rules win**. Required order:

1. **Apple-Siri** → same non-mainland proxy group as Apple-AI (e.g. a dedicated `🍎 Siri` group)
2. **Apple-AI** → **the same** proxy group / exit as Apple-Siri
3. **Claude-AI** (and other narrow AI sets) → their proxy groups
4. **Only then** broad Apple / China / GEOIP / LAN catch-alls
5. `FINAL`

**Why the same exit:** owner iPhone real-device testing found networked Siri queries only worked when `Apple-Siri.list` and `Apple-AI.list` shared one non-mainland-China proxy exit (a Taiwan node worked; `DIRECT` failed; at least one US node also failed, possibly node-specific). Pick an exit you verify works — this is operational experience, **not** an Apple-documented region requirement.

**RELEASE BLOCKER if inverted:** placing a broad Apple/China catch-all **between** Apple-Siri and Apple-AI (or before Apple-AI) can steal `gspe1-ssl.ls.apple.com`, `apple-relay.apple.com`, and other `*.apple.com` AI hosts into DIRECT / China policy so they never reach the proxy set.

```ini
[Proxy Group]
# Example: one dedicated group so Siri + Apple Intelligence share the same exit.
# Pick a non-mainland node you have verified works on-device (region is not Apple-mandated).
🍎 Siri = select, <your-verified-non-mainland-node>, <fallback-nodes...>

[Rule]
# 1) Siri / Search — SAME proxy group as Apple-AI (narrow)
RULE-SET,https://raw.githubusercontent.com/legolasljl/SurgeRule/main/Apple-Siri.list,🍎 Siri

# 2) Apple Intelligence / PCC / region probe / ChatGPT — BEFORE any Apple.com catch-all
#    Bind to the SAME group/exit as Apple-Siri above.
#    Apple documents purpose/reachability only — not a mandatory region or DIRECT policy.
RULE-SET,https://raw.githubusercontent.com/legolasljl/SurgeRule/main/Apple-AI.list,🍎 Siri

# 3) Other narrow AI (unchanged) — still before broad Apple/China catch-alls
RULE-SET,https://raw.githubusercontent.com/legolasljl/SurgeRule/main/Claude-AI.list,<POLICY>

# 4) Broad catch-alls LAST among service rules (examples — use your own lists/policies)
# RULE-SET,<your-apple-catchall>,DIRECT
# DOMAIN-SUFFIX,apple.com,DIRECT
# RULE-SET,<china-list>,DIRECT
# GEOIP,CN,DIRECT
# RULE-SET,LAN,DIRECT
# FINAL,<default>
```

Replace `🍎 Siri` / `<POLICY>` with your local proxy group names. The important part is that Apple-Siri and Apple-AI point at **one** verified non-mainland exit.

### Migration from `Apple-Siri-Direct.list` (DIRECT → shared proxy)

1. Change the raw URL  
   `https://raw.githubusercontent.com/legolasljl/SurgeRule/main/Apple-Siri-Direct.list`  
   → `https://raw.githubusercontent.com/legolasljl/SurgeRule/main/Apple-Siri.list`
2. Change the policy from `DIRECT` to the **same** proxy group used by `Apple-AI.list` (e.g. `🍎 Siri`). Do **not** leave Siri on DIRECT while Apple-AI is proxied.
3. Refresh / update the external resource in Surge after pull.
4. Optional: the old path `Apple-Siri-Direct.list` remains temporarily as a **deprecated duplicate** of the matchers (header warns against DIRECT). Prefer the new URL so a future removal of the old path does not break your config.

### Migration from the previous single `Apple-AI.list` subscription

Older `Apple-AI.list` mixed Siri hosts (e.g. `guzzoni`), PCC relays, Private Relay `mask*`, broad `ls.apple.com`, and `DOMAIN-KEYWORD,siri` into one proxy-bound set.

1. Keep using  
   `https://raw.githubusercontent.com/legolasljl/SurgeRule/main/Apple-AI.list`  
   as the **proxy** RULE-SET (backward-compatible URL; contents are the Apple Intelligence / PCC / ChatGPT set).
2. **Add** a new RULE-SET **immediately above** `Apple-AI.list`:  
   `https://raw.githubusercontent.com/legolasljl/SurgeRule/main/Apple-Siri.list` → **same** proxy group as Apple-AI (e.g. `🍎 Siri`).  
   Do **not** insert broad Apple/China catch-alls between Apple-Siri and Apple-AI.
3. Refresh / update the external resource in Surge after pull.
4. Re-check local inline / RULE-SET lines that force `guzzoni` / `smoot` / AI relays to a mismatched policy (or wrongly to DIRECT) **before** these RULE-SETs — earlier rules win; lines **after** these sets lose and are not the usual steal path.
5. Move any broad `DOMAIN-SUFFIX,apple.com` / Apple / China / GEOIP catch-alls to **after** Apple-AI (and preferably after Claude).
6. Optional: remove any local duplicate `DOMAIN*,guzzoni...` lines that only existed to patch the old list.

## Apple-Siri.list (→ same proxy as Apple-AI)

Raw URL:

```
https://raw.githubusercontent.com/legolasljl/SurgeRule/main/Apple-Siri.list
```

Deprecated alias (same matchers; do **not** bind to `DIRECT`):

```
https://raw.githubusercontent.com/legolasljl/SurgeRule/main/Apple-Siri-Direct.list
```

| Matcher | Documented / claimed purpose | Routing note |
| --- | --- | --- |
| `DOMAIN-SUFFIX,guzzoni.apple.com` | Siri & dictation ([Apple 101555](https://support.apple.com/en-us/101555)) | Bind to the **same** verified non-mainland exit as Apple-AI. Apple requires reachability; **does not** document DIRECT or a required region. |
| `DOMAIN-SUFFIX,smoot.apple.com` | Search incl. Siri/Spotlight/… ([Apple 101555](https://support.apple.com/en-us/101555)) | Same. Also affects non-Siri search surfaces — intentional narrow trade-off. |
| `DOMAIN-SUFFIX,siri.apple.com` | [Netify: Apple Siri](https://www.netify.ai/resources/hostnames/siri.apple.com); also [Aegis Apple.list](https://raw.githubusercontent.com/Thoseyearsbrian/Aegis/main/rules/Apple.list) | **Uncertain** — not in 101555 AI/Siri table; purpose label ≠ required egress region. |
| `DOMAIN,api-siri-prod.apple.com` | Prior list / Siri API host | **Uncertain** — not in 101555 table. |
| `DOMAIN,dejavu.apple.com` | [Netify: Apple Siri](https://www.netify.ai/resources/hostnames/dejavu.apple.com) | **Uncertain** — not in 101555 table. |
| `DOMAIN,sequoia.apple.com` | [Netify: Siri](https://www.netify.ai/resources/hostnames/sequoia.apple.com); [Aegis: 翻译服务接口](https://raw.githubusercontent.com/Thoseyearsbrian/Aegis/main/rules/Apple.list) | **Uncertain** — conflicting labels; exact DOMAIN only. |

## Apple-AI.list (→ same proxy as Apple-Siri)

Raw URL:

```
https://raw.githubusercontent.com/legolasljl/SurgeRule/main/Apple-AI.list
```

| Matcher | Documented / claimed purpose | Routing note |
| --- | --- | --- |
| `DOMAIN-SUFFIX,apple-relay.cloudflare.com` | Private Cloud Compute ([Apple 101555](https://support.apple.com/en-us/101555)) | Share the same verified non-mainland exit as Apple-Siri; Apple only requires access (Supports proxies: —). **Not** iCloud Private Relay. |
| `DOMAIN-SUFFIX,apple-relay.fastly-edge.com` | PCC ([Apple 101555](https://support.apple.com/en-us/101555)) | Same. |
| `DOMAIN,cp4.cloudflare.com` | PCC ([Apple 101555](https://support.apple.com/en-us/101555)) | Exact `DOMAIN` — avoid `DOMAIN-SUFFIX,cloudflare.com`. |
| `DOMAIN-SUFFIX,apple-relay.apple.com` | Apple Intelligence Extensions ([Apple 101555](https://support.apple.com/en-us/101555)) | ChatGPT extension path; shared egress with Siri is operational, not officially mandatory. |
| `DOMAIN-SUFFIX,apple-relay.mask.apple-dns.net` | Community: CNAME for `apple-relay.apple.com` ([hagezi share list](https://raw.githubusercontent.com/hagezi/dns-blocklists/main/share/apple-private-relay.txt); [v2fly apple-intelligence](https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/apple-intelligence)) | **Not** Private Relay `mask.apple-dns.net`. Restored after recheck. |
| `DOMAIN-SUFFIX,apple-carry-relay.cloudflare.com` | Community/hagezi after `staging.*` reports ([issue #6422](https://github.com/hagezi/dns-blocklists/issues/6422)) | **Uncertain** AI vs Private Relay; kept narrow; not in 101555. |
| `DOMAIN,gspe1-ssl.ls.apple.com` | Internet region / GCC probe (`/pep/gcc`) — [iRingo docs](https://nsringo.github.io/guide/GeoServices/location-service) | **Not** Siri voice. Exact DOMAIN only (not `*.ls.apple.com`). Egress region is operational, not Apple-mandated. |
| `DOMAIN,apple-relay.akamaized.net` | Prior list / [hagezi AI section](https://raw.githubusercontent.com/hagezi/dns-blocklists/main/share/apple-private-relay.txt) | **Uncertain** — absent from 101555 AI table. |
| `DOMAIN-SUFFIX,openai.com` / `chatgpt.com` / `oaistatic.com` / `oaiusercontent.com` | ChatGPT / OpenAI | Minimal companion domains; not a full OpenAI.list. |

PCC overview (architecture, not an allowlist): [Apple Security Research — Private Cloud Compute](https://security.apple.com/blog/private-cloud-compute/).

Maintained cross-checks (fetched for comparison; not copied wholesale):

- https://ruleset.isteed.cc/List/Source/AppleIntelligence.conf
- https://raw.githubusercontent.com/RocM301/Apple-Rule/main/Apple-AI.list
- https://raw.githubusercontent.com/hagezi/dns-blocklists/main/share/apple-private-relay.txt
- https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/apple-intelligence

### Intentionally excluded (avoid regressions)

- **iCloud Private Relay** (`mask.icloud.com`, `mask-h2.icloud.com`, `mask-api.icloud.com`, `mask.apple-dns.net`, related `mask-api.fe*.apple-dns.net`) — different service from PCC / from `apple-relay.mask.apple-dns.net` ([Apple 101555](https://support.apple.com/en-us/101555) iCloud section; [Apple Developer Private Relay prep](https://developer.apple.com/icloud/prepare-your-network-for-icloud-private-relay/)).
- **`DOMAIN-SUFFIX,ls.apple.com`** — Maps / GeoServices collateral ([issue discussion](https://github.com/Johnshall/Shadowrocket-ADBlock-Rules-Forever/issues/601)).
- **`DOMAIN-KEYWORD,siri`** — over-broad keyword catch.
- **`DOMAIN-SUFFIX,apps.mzstatic.com` / generic Apple CDN** — App Store asset catch-all.
- **`DOMAIN-SUFFIX,cloudflare.com` / bare `cp4` wildcards beyond the exact host** — CDN blast radius.

### Model download note

On-device Apple Intelligence model download is separate from PCC relay routing. If download stalls, some users temporarily send App Store / Apple CDN traffic through a supported-region node, then revert. This repo does **not** permanently proxy broad `mzstatic` / Apple CDN suffixes. Validate on device; do not treat Gestalt/wapi-only edits as proof of download or routing success.

## Optional Fake-IP / real-IP guidance (Surge `[General]`)

List files **cannot** set these. Edit your **local** profile only; do not expect RULE-SET subscription to mutate `[General]`.

Verified against Surge docs:

- [`always-real-ip`](https://manual.nssurge.com/profile/general.html) — Host List; exempts matching DNS queries from Fake-IP and returns a real upstream answer ([Advanced DNS](https://manual.nssurge.com/dns/advanced.html)). Optional if you observe Siri issues under Fake-IP, e.g. append (do not overwrite your whole list):  
  `guzzoni.apple.com, *.guzzoni.apple.com, *.siri.apple.com, *.smoot.apple.com`
- [`skip-proxy`](https://manual.nssurge.com/profile/general.html) — on iOS forces listed hosts onto Surge VIF instead of the HTTP system-proxy path; Surge explicitly states it is **not** a way to keep requests off a **proxy policy**. Use `RULE-SET …,<policy>` for routing (Siri + Apple-AI should share one verified proxy group; do not treat `skip-proxy` as a substitute for that). Do not treat screenshot advice that equates `skip-proxy` with “global DIRECT” as authoritative.

## iRingo / MitM coexistence (diagnosis, not certainty)

Modules that MitM `gspe1-ssl.ls.apple.com` or `smoot.apple.com` (e.g. iRingo LocationServices / Siri-related rewrites) **may** fight with region probes or search traffic after hardware/Gestalt changes. That is a conflict hypothesis from module design + overlapping hosts — **not** a guaranteed root cause, and this repo does **not** instruct blanket disabling of unrelated modules. Inspect Surge recent requests / MitM hostnames if Siri or eligibility still fails after correct RULE-SET order.

HTTPS interception of Apple hosts in [101555](https://support.apple.com/en-us/101555) is unsupported by Apple.

## Claude / Anthropic / Muse

Unchanged. Raw URL:

```
https://raw.githubusercontent.com/legolasljl/SurgeRule/main/Claude-AI.list
```

Place **after** Apple-AI and **before** broad Apple/China/GEOIP catch-alls (see Rule order above).

```ini
RULE-SET,https://raw.githubusercontent.com/legolasljl/SurgeRule/main/Claude-AI.list,<POLICY>
```

## Notes

- `PROCESS-NAME` rules only work on local clients (macOS / Windows / iOS apps); they have no effect on routers or remote gateways.
- `IP-ASN` requires an ASN database (e.g. Surge’s MaxMind / GeoIP ASN data). Without it, ASN rules are skipped.
- On-device success for CN-model iPhone + Mandarin Siri + Apple Intelligence is **not** claimed from list publication alone; confirm with device traffic captures after review. Shared non-mainland egress for Apple-Siri + Apple-AI is an operational finding from owner testing, not an Apple region mandate.
