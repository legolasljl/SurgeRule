# SurgeRule

Surge / Clash classical rule lists for external `RULE-SET` / `rule-providers` references.

List files contain **matchers and comments only** — **no policy / proxy-group names**. Bind a policy in your local config. These lists cannot set `[General]` options (`always-real-ip`, `skip-proxy`), cannot disable MitM modules, and cannot rewrite iRingo modules.

Default branch for raw URLs: `main`.

## Rule order (required)

Surge matches **top-down; earlier rules win**. Required order:

1. **Apple-Siri-Direct** → `DIRECT`
2. **Apple-AI** → user-selected supported-region proxy (often US)
3. **Claude-AI** (and other narrow AI sets) → their proxy groups
4. **Only then** broad Apple / China / GEOIP / LAN catch-alls
5. `FINAL`

**RELEASE BLOCKER if inverted:** placing a broad Apple/China catch-all **between** Direct and Apple-AI (or before Apple-AI) can steal `gspe1-ssl.ls.apple.com`, `apple-relay.apple.com`, and other `*.apple.com` AI hosts into DIRECT / China policy so they never reach the proxy set.

```ini
[Rule]
# 1) Siri / Search — DIRECT (narrow)
RULE-SET,https://raw.githubusercontent.com/legolasljl/SurgeRule/main/Apple-Siri-Direct.list,DIRECT

# 2) Apple Intelligence / PCC / region probe / ChatGPT — BEFORE any Apple.com catch-all
#    Prefer a low-latency node in an Apple Intelligence–supported region (often US).
#    Apple documents purpose/reachability only — not a mandatory US/DIRECT policy.
RULE-SET,https://raw.githubusercontent.com/legolasljl/SurgeRule/main/Apple-AI.list,<AI-POLICY>

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

Replace `<AI-POLICY>` / `<POLICY>` with your local proxy group names.

### Migration from the previous single `Apple-AI.list` subscription

Older `Apple-AI.list` mixed Siri hosts (e.g. `guzzoni`), PCC relays, Private Relay `mask*`, broad `ls.apple.com`, and `DOMAIN-KEYWORD,siri` into one proxy-bound set.

1. Keep using  
   `https://raw.githubusercontent.com/legolasljl/SurgeRule/main/Apple-AI.list`  
   as the **proxy** RULE-SET (backward-compatible URL; contents are now the proxy-only set).
2. **Add** a new RULE-SET **immediately above** `Apple-AI.list`:  
   `https://raw.githubusercontent.com/legolasljl/SurgeRule/main/Apple-Siri-Direct.list` → `DIRECT`.  
   Do **not** insert broad Apple/China catch-alls between Direct and Apple-AI.
3. Refresh / update the external resource in Surge after pull.
4. Re-check local inline / RULE-SET lines that force `guzzoni` / `smoot` / AI relays to a proxy (or wrongly to DIRECT) **before** these RULE-SETs — earlier rules win; lines **after** these sets lose and are not the usual steal path.
5. Move any broad `DOMAIN-SUFFIX,apple.com` / Apple / China / GEOIP catch-alls to **after** Apple-AI (and preferably after Claude).
6. Optional: remove any local duplicate `DOMAIN*,guzzoni...` lines that only existed to patch the old list.

## Apple-Siri-Direct.list (→ DIRECT)

Raw URL:

```
https://raw.githubusercontent.com/legolasljl/SurgeRule/main/Apple-Siri-Direct.list
```

| Matcher | Documented / claimed purpose | Routing note |
| --- | --- | --- |
| `DOMAIN-SUFFIX,guzzoni.apple.com` | Siri & dictation ([Apple 101555](https://support.apple.com/en-us/101555)) | Recommended DIRECT for CN-model Mandarin Siri. Apple requires reachability; **does not** document must-DIRECT. |
| `DOMAIN-SUFFIX,smoot.apple.com` | Search incl. Siri/Spotlight/… ([Apple 101555](https://support.apple.com/en-us/101555)) | Same. Also affects non-Siri search surfaces — intentional narrow trade-off. |
| `DOMAIN-SUFFIX,siri.apple.com` | [Netify: Apple Siri](https://www.netify.ai/resources/hostnames/siri.apple.com); also [Aegis Apple.list](https://raw.githubusercontent.com/Thoseyearsbrian/Aegis/main/rules/Apple.list) | **Uncertain** — not in 101555 AI/Siri table; purpose label ≠ must-DIRECT. |
| `DOMAIN,api-siri-prod.apple.com` | Prior list / Siri API host | **Uncertain** — not in 101555 table. |
| `DOMAIN,dejavu.apple.com` | [Netify: Apple Siri](https://www.netify.ai/resources/hostnames/dejavu.apple.com) | **Uncertain** — not in 101555 table. |
| `DOMAIN,sequoia.apple.com` | [Netify: Siri](https://www.netify.ai/resources/hostnames/sequoia.apple.com); [Aegis: 翻译服务接口](https://raw.githubusercontent.com/Thoseyearsbrian/Aegis/main/rules/Apple.list) | **Uncertain** — conflicting labels; exact DOMAIN only. |

## Apple-AI.list (→ user-selected proxy)

Raw URL:

```
https://raw.githubusercontent.com/legolasljl/SurgeRule/main/Apple-AI.list
```

| Matcher | Documented / claimed purpose | Routing note |
| --- | --- | --- |
| `DOMAIN-SUFFIX,apple-relay.cloudflare.com` | Private Cloud Compute ([Apple 101555](https://support.apple.com/en-us/101555)) | Supported-region proxy is a common operational choice; Apple only requires access (Supports proxies: —). **Not** iCloud Private Relay. |
| `DOMAIN-SUFFIX,apple-relay.fastly-edge.com` | PCC ([Apple 101555](https://support.apple.com/en-us/101555)) | Same. |
| `DOMAIN,cp4.cloudflare.com` | PCC ([Apple 101555](https://support.apple.com/en-us/101555)) | Exact `DOMAIN` — avoid `DOMAIN-SUFFIX,cloudflare.com`. |
| `DOMAIN-SUFFIX,apple-relay.apple.com` | Apple Intelligence Extensions ([Apple 101555](https://support.apple.com/en-us/101555)) | ChatGPT extension path; supported-region egress is operational, not officially mandatory. |
| `DOMAIN-SUFFIX,apple-relay.mask.apple-dns.net` | Community: CNAME for `apple-relay.apple.com` ([hagezi share list](https://raw.githubusercontent.com/hagezi/dns-blocklists/main/share/apple-private-relay.txt); [v2fly apple-intelligence](https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/apple-intelligence)) | **Not** Private Relay `mask.apple-dns.net`. Restored after recheck. |
| `DOMAIN-SUFFIX,apple-carry-relay.cloudflare.com` | Community/hagezi after `staging.*` reports ([issue #6422](https://github.com/hagezi/dns-blocklists/issues/6422)) | **Uncertain** AI vs Private Relay; kept narrow; not in 101555. |
| `DOMAIN,gspe1-ssl.ls.apple.com` | Internet region / GCC probe (`/pep/gcc`) — [iRingo docs](https://nsringo.github.io/guide/GeoServices/location-service) | **Not** Siri voice. **Uncertain must-US**; exact DOMAIN only (not `*.ls.apple.com`). |
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
- [`skip-proxy`](https://manual.nssurge.com/profile/general.html) — on iOS forces listed hosts onto Surge VIF instead of the HTTP system-proxy path; Surge explicitly states it is **not** a way to keep requests off a **proxy policy**. Use `RULE-SET …,DIRECT` for DIRECT routing. Do not treat screenshot advice that equates `skip-proxy` with “global DIRECT” as authoritative.

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
- On-device success for CN-model iPhone + Mandarin Siri + Apple Intelligence is **not** claimed from list publication alone; confirm with device traffic captures after review.
