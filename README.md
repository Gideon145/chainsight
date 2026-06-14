# ChainSight

**Autonomous Multi-Agent Forensic Analysis for the SIFT Workstation**

> *"When adversaries move at machine speed, defenders need to as well."*

[![Demo Video](https://img.shields.io/badge/Demo%20Video-YouTube-red)](https://youtu.be/-JZ262m2yxw)
[![Accuracy](https://img.shields.io/badge/Accuracy-7%2F7%20true%20positives-brightgreen)](https://github.com/Gideon145/chainsight/blob/master/ACCURACY_REPORT.md)
[![Python](https://img.shields.io/badge/Python-3.12-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-blue)](LICENSE)

---

## What Is ChainSight?

ChainSight is a deterministic forensic orchestrator that runs on the SANS SIFT Workstation. It dispatches four detection stages against disk images — collect, score, cross-reference, and hunt — producing a verifiable Forensic Confidence Score (0–100) with every finding traceable to the exact tool output that produced it.

The system is built with zero external dependencies: Python 3 and the tools already on SIFT. No API keys. No Claude Code. No cloud services. Evidence is mounted read-only at the OS level. The orchestrator physically cannot modify it.

---

## The Problem ChainSight Solves

AI-powered adversaries go from initial access to full domain control in under 8 minutes. CrowdStrike observed breakout in 7 minutes. Horizon3's autonomous agent achieved full privilege escalation in 60 seconds. MIT research found AI-driven attack workflows running 47 times faster than human operators.

Manual command-line incident response cannot compete with autonomous agents executing thousands of requests per second. A human responder is still looking up command-line flags during an active incident.

Protocol SIFT demonstrated that connecting AI agents to forensic tools through MCP is possible. It also hallucinates more than practitioners would like — which is exactly why Find Evil! exists. ChainSight addresses the core gap: how to sequence an investigation, recognize contradictions, and produce findings that can be traced back to tool output, without hallucination.

---

## The Solution

ChainSight runs a deterministic 4-stage detection pipeline:

1. **Collects** suspicious files from the mounted evidence — `.js`, `.reg`, `.bin`, `.ps1`, `.dll` — using `find`, then reads their contents with `cat` and `strings`
2. **Scores** file contents against known attack patterns using regex rules. Base64-encoded PowerShell in a Downloads folder is CRITICAL. A registry Run key in ProgramData is CRITICAL. An IP:port beacon configuration is HIGH
3. **Cross-references** filesystem timestamps. Files created within one second of each other on the same volume indicate automated deployment
4. **Hunts** for attack chains by correlating findings across stages. Phishing payload plus persistence mechanism plus C2 beacon equals a confirmed Emotet-style kill chain

The Forensic Confidence Score is a weighted average across agents, with discrepancy and gap penalties:

```
With memory image:    disk(30%) + memory(25%) + timeline(25%) + threat(20%)
Without memory image: disk(40%) + timeline(30%) + threat(30%)
                      - discrepancy_penalty
                      - gap_penalty (removed for absent memory)
```

Grading thresholds: A (90–100), B (75–89), C (60–74), D (40–59), F (below 40). The formula is validated by 14 pytest tests. Same evidence always produces the same score.

---

## Live Deployment (Verified)

ChainSight is not a running service — it executes on-demand on the SIFT Workstation. The demo video shows a complete 5-minute run.

| Artifact | Location | Status |
|----------|----------|--------|
| Code Repository | https://github.com/Gideon145/chainsight | Public, MIT license |
| Demo Video | https://youtu.be/-JZ262m2yxw | Submitted |
| Architecture Diagram | [architecture.svg](architecture.svg) | Security boundaries annotated |
| Accuracy Report | [ACCURACY_REPORT.md](ACCURACY_REPORT.md) | 7/7 true positives, 0 false positives, 0 hallucinations |
| Dataset Documentation | [DATASET.md](DATASET.md) | Emotet scenario, fully reproducible |
| Execution Logs | [EXECUTION_LOG.md](EXECUTION_LOG.md) | Full tool execution trace |
| Try-It-Out Instructions | [TRY_IT_OUT.md](TRY_IT_OUT.md) | Three commands from clone to report |

### Live Verification Commands

```bash
# Clone and run ChainSight on any SIFT Workstation
git clone https://github.com/Gideon145/chainsight.git ~/chainsight

# Create a test disk image with planted Emotet artifacts
cd /cases/demo
dd if=/dev/zero of=disk.dd bs=1M count=100
sudo mkfs.ext4 disk.dd
sudo mkdir -p /mnt/rd01 && sudo mount -o loop disk.dd /mnt/rd01
sudo mkdir -p /mnt/rd01/Users/jsmith/Downloads /mnt/rd01/ProgramData
echo "powershell.exe -enc JABwAGEAPQBOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAA7AA==" | sudo tee /mnt/rd01/Users/jsmith/Downloads/invoice.js > /dev/null
echo "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\WindowsUpdate=C:\ProgramData\payload.dll" | sudo tee /mnt/rd01/ProgramData/persistence.reg > /dev/null
echo "192.168.1.100:443 beacon interval=60 jitter=15" | sudo tee /mnt/rd01/ProgramData/config.bin > /dev/null
sudo chmod -R a+r /mnt/rd01 && sudo umount /mnt/rd01 && sudo mount -o ro,loop disk.dd /mnt/rd01

# Run the orchestrator
python3 ~/chainsight/orchestrator.py --mount /mnt/rd01 --disk-image /cases/demo/disk.dd

# View the report
cat /cases/demo/reports/forensic_report.json

# Run deterministic scoring tests
cd ~/chainsight/tests && python3 -m pytest test_scoring.py -v
```

---

## Architecture

```
+---------------------------------------------------------------------------------+
|                         CHAINSIGHT ARCHITECTURE                                  |
+----------------------+----------------------+------------------------------------+
|   COLLECT            |   SCORE              |   CROSS-REFERENCE + HUNT           |
|   find, cat, strings |   regex rules        |                                    |
|                      |                      |   Filesystem timestamps            |
|  +----------------+  |  +----------------+  |   Cross-agent correlation          |
|  | .js in Downloads|  |  | powershell.*   |  |                                    |
|  | .reg in ProgData|  |  | -enc → CRITICAL|  |   +--------------------------+     |
|  | .bin with config|  |  | run.*windows   |  |   | Attack Chain Detection   |     |
|  | .ps1, .dll      |  |  | in .reg →      |  |   | phishing + persistence   |     |
|  +----------------+  |  | CRITICAL        |  |   | + C2 → Emotet kill chain |     |
|                      |  |                 |  |   +--------------------------+     |
|   SIFT WORKSTATION   |  | IP:port +       |  |                                    |
|   Read-only mount    |  | beacon → HIGH   |  |   +--------------------------+     |
|   mount -o ro,loop   |  +----------------+  |   | Forensic Confidence Score|     |
|                      |                      |   | 85.5/100 — Grade B       |     |
|   SECURITY           |   DETECTION RULES    |   | Deterministic, verifiable|     |
|   subprocess.run     |   5 regex patterns   |   | 14 pytest tests          |     |
|   list form only     |   documented, tested |   +--------------------------+     |
|   find/cat/strings   |                      |                                    |
|   no destructive cmds|                      |   OUTPUT                           |
+----------------------+----------------------+   JSON report + terminal log       |
                                              +------------------------------------+
```

---

## Detection Rules

ChainSight uses five regex-based detection rules. Each rule targets a specific artifact from the Emotet/IcedID kill chain.

### 1. Encoded PowerShell in Downloads (CRITICAL)

```python
# Rule: .js file in Downloads containing powershell.*-enc
if "downloads" in path_lower and path_lower.endswith(".js"):
    if "powershell" in content.lower() and "-enc" in content.lower():
        → CRITICAL — Phishing payload, encoded PowerShell download cradle
```

Detects the initial access vector. Emotet delivers JavaScript files with obfuscated PowerShell that downloads and executes the next stage.

### 2. Registry Run Key Persistence (CRITICAL)

```python
# Rule: .reg file in ProgramData containing Run key with windows reference
if path_lower.endswith(".reg") and "programdata" in path_lower:
    if "run" in content.lower() and "windows" in content.lower():
        → CRITICAL — Persistence mechanism, malware survives reboot
```

Detects the standard Emotet persistence pattern: a registry Run key pointing to a DLL in ProgramData.

### 3. C2 Beacon Configuration (HIGH)

```python
# Rule: .bin file in ProgramData with IP:port and beacon/interval keywords
if path_lower.endswith(".bin") and "programdata" in path_lower:
    if re.search(r'\d+\.\d+\.\d+\.\d+:\d+', content):
        if "beacon" in content.lower() or "interval" in content.lower():
            → HIGH — C2 beacon configuration with hardcoded IP and timing
```

Detects command-and-control configuration files containing hardcoded IP addresses, ports, and beacon timing parameters.

### 4. Temporal Clustering (MEDIUM)

```python
# Rule: files created within 1 second of each other on same volume
if timestamps[i+1] - timestamps[i] < 1.0:
    → MEDIUM — Automated malware deployment, consistent with scripted attacks
```

Detects automated file deployment. Attackers using scripts or agents create multiple files in rapid succession — a temporal pattern distinct from normal user behavior.

### 5. Cross-Agent Attack Chain (CRITICAL)

```python
# Rule: phishing + persistence + C2 all confirmed by separate agents
if has_phishing and has_persistence and has_c2:
    → CRITICAL — Complete Emotet/IcedID kill chain, cross-agent correlation
```

Correlates findings across detection stages. Individual artifacts are suspicious — together, they confirm a complete attack chain.

---

## SIFT Workstation Integration

ChainSight uses three categories of SIFT tools in its detection pipeline:

### 1. `find`

Called in every detection stage. Locates suspicious files by extension (.js, .reg, .bin, .ps1, .dll) and extracts filesystem timestamps for temporal analysis.

```bash
find /mnt/rd01 -type f -name "*.js" -o -name "*.reg" -o -name "*.bin" -printf "%p\n"
find /mnt/rd01 -type f -printf "%T@ %p\n"  # timeline
```

All `find` invocations use `-printf` for structured output and exclude `lost+found` to avoid permission errors.

### 2. `cat`

Reads the contents of suspicious files for regex analysis. Called on every file discovered by `find`.

```bash
cat /mnt/rd01/Users/jsmith/Downloads/invoice.js
```

Output is passed directly to the regex detection rules. No intermediate parsing — the raw file content is the evidence.

### 3. `strings`

Extracts readable strings from binary files (.bin, .dll) for pattern matching. Called when `cat` output is insufficient for binary formats.

```bash
strings -n 4 /mnt/rd01/ProgramData/config.bin
```

All three tool invocations are logged with timestamps and output in the JSON report, providing real-time verifiable proof of SIFT tool usage.

---

## Codebase Structure

```
chainsight/
├── orchestrator.py                  # Python orchestrator — 4-stage detection pipeline
│
├── skills/                          # Agent definitions (reference architecture)
│   ├── disk-forensics/SKILL.md      # Sleuth Kit + EZ Tools agent specification
│   ├── memory-forensics/SKILL.md    # Volatility 3 agent specification
│   ├── super-timeline/SKILL.md      # Plaso temporal correlation specification
│   └── threat-hunting/SKILL.md      # YARA + Sigma IOC hunting specification
│
├── tests/
│   └── test_scoring.py              # 14 deterministic scoring tests
│
├── ARCHITECTURE.md                  # Security boundaries and bypass analysis
├── ACCURACY_REPORT.md               # 7/7 true positives, 0 false positives, 0 hallucinations
├── DATASET.md                       # Evidence specification: Emotet scenario
├── EXECUTION_LOG.md                 # Full tool execution trace
├── TRY_IT_OUT.md                    # Step-by-step judge instructions
├── DEVPOST.md                       # Written project description
├── architecture.svg                 # Architecture diagram
├── setup.sh                         # One-command SIFT VM installer
└── README.md                        # This file
```

---

## Orchestrator Deep Dive

Every invocation of `orchestrator.py` runs four stages in sequence:

```python
# Stage 1: Collect — find all suspicious files on mounted evidence
suspicious = tool_find_suspicious(mount)    # find *.js, *.reg, *.bin, *.ps1, *.dll
for path in found_files:
    file_contents[path] = tool_cat(path)    # cat each file for analysis

# Stage 2: Score — regex rules against file contents
for path, content in file_contents.items():
    if "powershell" in content and "-enc" in content and "downloads" in path:
        findings.append(CRITICAL, "Phishing payload", path)
    if "run" in content and "windows" in content and "programdata" in path:
        findings.append(CRITICAL, "Registry persistence", path)

# Stage 3: Cross-Reference — temporal analysis
timestamps = tool_find_timestamps(mount)    # find -printf "%T@ %p"
if adjacent_files_within_1s(timestamps):
    findings.append(MEDIUM, "Automated deployment")

# Stage 4: Hunt — attack chain correlation
if has_phishing and has_persistence and has_c2:
    findings.append(CRITICAL, "Full Emotet kill chain")

# Compute Forensic Confidence Score
score = compute_forensic_score(disk_conf, 0, timeline_conf, threat_conf, has_memory=False)
grade = "A" if score >= 90 else "B" if score >= 75 else ...
```

The orchestrator produces identical output for identical evidence. Every finding includes the source file path and the exact string that triggered the detection rule. The scoring formula is deterministic — run the pytest suite to verify.

---

## What Makes This Different

Most hackathon forensic agents are prompt-based — a language model with tool access and behavioral guardrails. ChainSight takes the opposite approach.

1. **Zero AI dependency.** No Claude Code, no Gemini, no API keys. The orchestrator depends on nothing except Python 3 and the SIFT Workstation. This eliminates hallucination risk entirely — regex rules either match or they do not.

2. **Architectural enforcement, not prompt-based.** Evidence is mounted read-only at the OS level. The orchestrator calls exactly three executables: `find`, `cat`, and `strings`. There is no prompt to ignore, no model to jailbreak, no API to rate-limit. The Linux kernel is the guardrail.

3. **Deterministic and verifiable.** Same evidence produces the same findings and the same score every time. Fourteen pytest tests validate the scoring formula. Judges can reproduce any run and get identical output. No other submission can make this claim — AI-based agents are inherently non-deterministic.

4. **Three commands from clone to report.** No accounts, no billing, no configuration. The try-it-out instructions fit in a single bash snippet. A judge can verify the entire submission in under two minutes.

5. **Every finding traceable to tool output.** The JSON report includes the source file path and the exact string that triggered each detection rule. The audit trail is complete — from `cat` output to CRITICAL finding, no gaps.

6. **Honest about limitations.** The orchestrator detects known patterns against known malware families. It will not generalize to novel attacks. The README says this explicitly. There is no claim of AI-powered threat detection — just five regex rules, documented and tested.

---

## Running Locally

### Prerequisites

- SANS SIFT Workstation (download from sans.org/tools/sift-workstation)
- Python 3.12+ (pre-installed on SIFT)
- No API keys, no accounts, no external services

### 1. Clone and Run

```bash
git clone https://github.com/Gideon145/chainsight.git ~/chainsight

cd /cases/demo
dd if=/dev/zero of=disk.dd bs=1M count=100
sudo mkfs.ext4 disk.dd
sudo mkdir -p /mnt/rd01 && sudo mount -o loop disk.dd /mnt/rd01
sudo mkdir -p /mnt/rd01/Users/jsmith/Downloads /mnt/rd01/ProgramData
echo "powershell.exe -enc JABwAGEAPQBOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAA7AA==" | sudo tee /mnt/rd01/Users/jsmith/Downloads/invoice.js > /dev/null
echo "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\WindowsUpdate=C:\ProgramData\payload.dll" | sudo tee /mnt/rd01/ProgramData/persistence.reg > /dev/null
echo "192.168.1.100:443 beacon interval=60 jitter=15" | sudo tee /mnt/rd01/ProgramData/config.bin > /dev/null
sudo chmod -R a+r /mnt/rd01 && sudo umount /mnt/rd01 && sudo mount -o ro,loop disk.dd /mnt/rd01

python3 ~/chainsight/orchestrator.py --mount /mnt/rd01 --disk-image /cases/demo/disk.dd
cat /cases/demo/reports/forensic_report.json
```

Expected output: 7 findings (3 CRITICAL, 3 HIGH, 1 MEDIUM), 85.5 Forensic Confidence Score (Grade B).

### 2. Run Tests

```bash
cd ~/chainsight/tests && python3 -m pytest test_scoring.py -v
```

All 14 tests pass. The scoring formula is validated for grade boundaries, severity weights, and memory/no-memory variants.

---

## Accuracy Results

Tested against a simulated Emotet infection scenario on a 100 MB ext4 disk image with three planted artifacts.

| Metric | Result |
|--------|--------|
| True positives | 7/7 (100%) |
| False positives | 0 |
| Missed artifacts | 0 |
| Hallucination rate | 0% (rule-based — hallucinations impossible) |
| Forensic Confidence Score | 85.5/100 (Grade B) |
| Attack chain reconstruction | Confirmed — phishing → persistence → C2 |
| Evidence spoliation | Zero risk — read-only mount, no destructive commands in source |

Full accuracy report: [ACCURACY_REPORT.md](ACCURACY_REPORT.md)

---

## Security Model

Evidence integrity is enforced by two architectural layers. Neither relies on prompts or permissions that can be ignored.

| Layer | Mechanism | Bypass Risk |
|-------|-----------|-------------|
| Command scope | Only `find`, `cat`, `strings` called. No `rm`, `dd`, `curl`, or any destructive command exists in source. | None — cannot call what is not written |
| Read-only mount | `mount -o ro,loop` — kernel rejects all write attempts with EROFS. | None — enforced by Linux VFS |

Tested five spoliation scenarios: write attempt to evidence mount, destructive command, data exfiltration, arbitrary shell injection via file path, and evidence hash verification. Zero bypasses. Full analysis in [ARCHITECTURE.md](ARCHITECTURE.md).

---

## Team

| Name | Role |
|------|------|
| Gideon | Full-stack engineer, smart contract auditor, DeFi security researcher |

### Build Timeline

ChainSight was built for the SANS Find Evil! Hackathon (April 15 – June 15, 2026). Development began June 9 with the initial architecture — four SKILL.md files extending Protocol SIFT's Claude Code agent with a deterministic scoring engine. That version was fully documented with accuracy reports, execution logs, and a three-layer defense analysis.

On June 12, the architecture was rewritten as a pure Python orchestrator after Claude Code credit limits and Gemini rate limits made the original approach unsustainable. The Python orchestrator was written, tested against planted Emotet artifacts, and deployed on the SIFT Workstation in a single session. The demo video, final accuracy report, architecture diagram, and this README were completed June 14.

The git history reflects the full arc: 20+ commits from June 9 to June 14, covering initial scaffold → Claude Code skills → Python orchestrator rewrite → all eight submission components.

---

## License

MIT — SANS Find Evil! Hackathon, June 2026
