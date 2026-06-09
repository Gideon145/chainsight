# Threat Hunting Agent

Sweep evidence for known-bad indicators and behavioral anomalies.
YARA rules, Sigma rules, IOC matching, and anomaly detection.

## When to use
- After baseline analysis is complete (disk + memory processed)
- Have a set of IOCs (file hashes, IPs, domains, mutex names)
- Need to sweep for known threat actor TTPs
- Looking for anomalous patterns that evade signature-based detection

## Tool chain
- **YARA** — `yara`
- **Sigma** — rule-to-grep translation for log files
- **hashdeep** — `md5deep`, `sha256deep`

## Process

### Step 1 — IOC ingestion
Parse `./iocs/` directory for:
- `hashes.txt` — one SHA256 per line
- `ips.txt` — one IPv4 per line
- `domains.txt` — one domain per line
- `mutexes.txt` — mutex names from threat intel

### Step 2 — YARA sweep
```
yara -r ./rules/ ./exports/disk/recovered/
yara -r ./rules/ /mnt/rd01/
```

**Rules directory** should contain:
- `c2_beacons.yar` — C2 communication patterns
- `ransomware.yar` — ransomware artifacts
- `cred_theft.yar` — credential dumping tools
- `lolbins.yar` — living-off-the-land binaries
- `custom.yar` — case-specific rules from threat intel

### Step 3 — Hash sweep
```
sha256deep -r /mnt/rd01/ > ./exports/threat/all_hashes.txt
```
Cross-reference against `./iocs/hashes.txt` AND VirusTotal (if MCP-connected).

### Step 4 — Sigma rule translation
Translate high-priority Sigma rules to grep patterns for raw event logs:
```
# Sigma: Suspicious PowerShell DownloadString
grep -r "DownloadString\|Invoke-WebRequest\|Net.WebClient" ./exports/disk/evtx/

# Sigma: Service Execution from Temp
grep -r "7045.*Temp" ./exports/disk/evtx/System.csv

# Sigma: WMI Persistence
grep -r "__EventFilter\|__IntervalCommandLine\|ActiveScriptEventConsumer" ./exports/disk/evtx/
```

### Step 5 — Anomaly scoring
For each finding, compute anomaly score (0-100):

```
anomaly = (hash_match * 40) + (yara_match * 35) + (sigma_match * 25)
         + (multi_source * 20) - (legit_signed * 30)
```

| Factor | Weight |
|--------|--------|
| Hash matches known IOC | +40 |
| YARA rule matches | +35 |
| Sigma rule matches | +25 |
| Finding corroborated by disk AND memory | +20 |
| Binary is signed by Microsoft/trusted vendor | -30 |

Score >60 = HIGH confidence threat. 30-60 = suspicious. <30 = likely false positive.

## Output format

```json
{
  "artifact_type": "threat_hunt",
  "iocs_matched": { "hashes": [], "ips": [], "domains": [], "mutexes": [] },
  "yara_hits": [
    { "rule": "", "file": "", "anomaly_score": 0, "confidence": "high" }
  ],
  "sigma_hits": [],
  "highest_scoring": { "finding": "", "score": 0 }
}
```

## Anti-rationalization

| Excuse | Rebuttal |
|--------|----------|
| "No IOCs provided, skipping" | Run anomaly detection anyway. Behavioral anomalies don't need IOCs. |
| "YARA rules are outdated" | Run them anyway. Old malware is still malware. 0-day detection is a bonus, not the goal. |
| "Sigma rules don't match" | That IS a finding. Document what was tested and found clean. Negative results are evidence. |
| "File is signed, must be safe" | Signed malware exists (stolen certs, LODEINFO, Zloader). Signed = lower score, not clean. |

## Severity mapping

| Finding | Severity |
|---------|----------|
| Known IOC hash match + YARA hit | CRITICAL |
| YARA hit on credential theft tool | CRITICAL |
| C2 beacon pattern match | CRITICAL |
| Sigma match + disk evidence corroboration | HIGH |
| Isolated YARA hit (single rule, no corroboration) | MEDIUM |
| Anomaly score 30-60 | LOW |
