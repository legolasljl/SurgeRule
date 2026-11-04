# SurgeRule

Surge / Clash classical rule lists for external `RULE-SET` / `rule-providers` references.

List files contain matchers only — **no policy / proxy-group names**. Bind a policy in your local config.

## Claude / Anthropic / Muse

Raw URL:

```
https://raw.githubusercontent.com/legolasljl/SurgeRule/main/Claude-AI.list
```

Surge example (replace `<POLICY>` with your proxy group):

```
RULE-SET,https://raw.githubusercontent.com/legolasljl/SurgeRule/main/Claude-AI.list,<POLICY>
```

### Notes

- `PROCESS-NAME` rules only work on local clients (macOS / Windows / iOS apps); they have no effect on routers or remote gateways.
- `IP-ASN` requires an ASN database (e.g. Surge’s MaxMind / GeoIP ASN data). Without it, ASN rules are skipped.
