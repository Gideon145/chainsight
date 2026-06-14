# ChainSight

A deterministic forensic orchestrator that runs on the SIFT Workstation. Four agents analyze disk images against known attack patterns, cross-reference findings, and produce a verifiable confidence score. No API keys. No external dependencies. Python 3 and the tools already on SIFT.

Built for the [SANS Find Evil! Hackathon](https://findevil.devpost.com/). All eight submission components included.

---

## What ChainSight does

ChainSight accepts a mounted disk image and runs four detection stages against it:

1. **Collect** — `find` locates suspicious files (.js, .reg, .bin, .ps1, .dll). `cat` and `strings` read their contents.
2. **Score** — Regex rules match contents against known attack patterns. Base64-encoded PowerShell in a Downloads folder is CRITICAL. A registry Run key in ProgramData is CRITICAL. An IP:port beacon configuration is HIGH.
3. **Cross-reference** — Filesystem timestamps are compared. Files created within one second of each other indicate automated deployment.
4. **Hunt** — Findings from the previous stages are correlated. Phishing payload plus persistence mechanism plus C2 beacon equals a confirmed Emotet-style kill chain.

Each finding carries the exact tool output line that produced it. The confidence score is a weighted average of per-agent confidence and inter-agent correlation penalties, validated by fourteen deterministic tests.

The orchestrator runs in five seconds on a stock SIFT Workstation. Same evidence produces the same findings and the same score every time.

---

## Why this approach

The hackathon brief lists four architectural patterns. ChainSight is closest to Option 2 — a purpose-built server that exposes structured functions instead of generic shell commands. The orchestrator calls exact tool names (`find`, `cat`, `strings`) via `subprocess.run` in list form. No shell. No arbitrary commands. The agent physically cannot run `rm`, `dd`, `curl`, or any destructive tool because the orchestrator never invokes them.

We started with Claude Code skills and Google Gemini. Claude required credits we did not have. Gemini's free tier allowed twenty requests per day. Each API failure forced removal of a dependency. The final version depends on nothing except Python 3 and the SIFT Workstation.

This aligns with what the judging criteria prioritize: architectural enforcement over prompt-based guardrails. Evidence is mounted read-only at the OS level. The orchestrator cannot modify it. There is no prompt to ignore, no model to hallucinate, no API to rate-limit.

---

## Judging criteria addressed

The hackathon evaluates submissions on six criteria. Here is where ChainSight stands on each.

**Autonomous execution quality (tiebreaker).** The orchestrator runs without human intervention. It sequences its own approach: collect files, score contents, cross-reference timestamps, correlate into an attack chain. The pipeline is linear by design — each stage feeds the next. There is no agent loop that can spiral or stall.

**IR accuracy.** Seven findings against planted Emotet artifacts. Three CRITICAL (encoded PowerShell, registry persistence, full attack chain). Three HIGH (C2 beacon, initial access, C2 confirmation). One MEDIUM (temporal clustering). Zero false positives. Zero hallucinated findings — impossible with deterministic regex rules. Full accuracy report in ACCURACY_REPORT.md.

**Breadth and depth of analysis.** The current implementation handles disk images. Three artifact types are detected: phishing payloads, persistence mechanisms, and C2 configurations. The SKILL.md files define detection logic for memory forensics and threat hunting — those stages are designed but not wired in the current orchestrator. We prioritized depth on disk forensics over shallow coverage of all evidence types.

**Constraint implementation.** Guardrails are architectural, not prompt-based. Three layers: (1) Evidence mounted read-only (`mount -o ro,loop`) — kernel-enforced, zero bypass risk. (2) `subprocess.run` with list-form commands — no shell, no injection possible. (3) Exact tool names only — the orchestrator can call `find`, `cat`, and `strings`. It cannot call anything else. Documented with bypass analysis in ARCHITECTURE.md.

**Audit trail quality.** Every finding in the JSON report includes the source file path and the exact string that triggered the detection rule. Judges can trace `F-01: CRITICAL persistence.reg` back to the `cat` output that produced it. The scoring formula is deterministic and tested — run the pytest suite to verify.

**Usability and documentation.** Three commands from clone to report. No accounts, no billing, no configuration. Every submission component is a markdown file in the repository. Step-by-step instructions in TRY_IT_OUT.md. Demo video shows the full five-minute run.

---

## How to run

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

Expected output: seven findings (three CRITICAL), 85.5 Forensic Confidence Score (Grade B).

---

## Repository structure

```
chainsight/
├── orchestrator.py              # Python orchestrator — 4-stage detection pipeline
├── skills/                      # Agent definitions (disk, memory, timeline, threat)
│   ├── disk-forensics/SKILL.md
│   ├── memory-forensics/SKILL.md
│   ├── super-timeline/SKILL.md
│   └── threat-hunting/SKILL.md
├── tests/
│   └── test_scoring.py          # 14 deterministic scoring tests
├── ARCHITECTURE.md              # Security boundaries and bypass analysis
├── ACCURACY_REPORT.md           # 7 findings, 0 false positives, 0 hallucinations
├── DATASET.md                   # Evidence specification and reproducibility
├── EXECUTION_LOG.md             # Full tool execution trace
├── TRY_IT_OUT.md                # Step-by-step judge instructions
├── DEVPOST.md                   # Written project description
├── architecture.svg             # Architecture diagram
└── setup.sh                     # One-command SIFT VM installer
```

---

## Submission artifacts

All eight components required by the hackathon:

- **Code repository** — [github.com/Gideon145/chainsight](https://github.com/Gideon145/chainsight), MIT license
- **Demo video** — [5-minute screencast](https://youtu.be/-JZ262m2yxw) with live terminal execution
- **Architecture diagram** — [architecture.svg](architecture.svg), security boundaries annotated
- **Written description** — [DEVPOST.md](DEVPOST.md)
- **Dataset documentation** — [DATASET.md](DATASET.md)
- **Accuracy report** — [ACCURACY_REPORT.md](ACCURACY_REPORT.md)
- **Try-it-out instructions** — [TRY_IT_OUT.md](TRY_IT_OUT.md)
- **Execution logs** — [EXECUTION_LOG.md](EXECUTION_LOG.md)

---

## Detection rules

The orchestrator uses five regex-based detection rules. Each is documented with the pattern, severity, and the real-world attack it targets.

| Rule | Pattern | Severity | Targets |
|------|---------|----------|---------|
| Encoded PowerShell in Downloads | `powershell.*-enc` in `.js` files under `Downloads` | CRITICAL | Emotet/IcedID initial access |
| Registry persistence in ProgramData | `run` and `windows` in `.reg` files under `ProgramData` | CRITICAL | Emotet Run key persistence |
| C2 beacon configuration | `\d+\.\d+\.\d+\.\d+:\d+` with `beacon` or `interval` in `.bin` files | HIGH | C2 setup pattern |
| Temporal clustering | File timestamps within 1 second on same volume | MEDIUM | Automated malware deployment |
| Cross-agent attack chain | Phishing + persistence + C2 all confirmed by separate agents | CRITICAL | Full Emotet kill chain |

---

## Forensic Confidence Score

The score is a weighted average across agents, adjusted for inter-agent discrepancies and missing coverage areas.

When a memory image is available: `disk(30%) + memory(25%) + timeline(25%) + threat(20%)`, minus discrepancy and gap penalties.

When no memory image is provided: `disk(40%) + timeline(30%) + threat(30%)`, with gap penalties removed for the missing agent.

Grading thresholds: A (90–100), B (75–89), C (60–74), D (40–59), F (below 40). The formula and weights are validated by fourteen pytest tests. Same evidence always produces the same score.

---

## Limitations

The orchestrator detects known patterns against known malware families. It will not generalize to novel attacks. The rules are ten lines of Python each — they can be extended, but they will never reason about an unfamiliar artifact the way an analyst would.

The current implementation handles disk images only. Memory forensics, live endpoint triage, and SIEM correlation are designed in the SKILL.md files but not wired into the orchestrator.

Accuracy has been assessed against one scenario (Emotet). Performance against ransomware, APT-level adversaries, or clean systems is untested.

No AI is used in detection. This eliminates hallucination risk and API dependency. It also means the orchestrator cannot perform semantic analysis of novel threat patterns. Adding a language model for zero-day detection, with the existing rule engine as a verification layer, is a planned extension.

---

## License

MIT — SANS Find Evil! Hackathon, June 2026
