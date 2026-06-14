# Try-It-Out Instructions — ChainSight

Judges can run ChainSight against the provided sample case data or their own evidence files. No API keys required. No Claude Code. Pure Python + SIFT tools.

---

## Option A: Quickest path (SIFT VM + ChainSight)

### Prerequisites
- SANS SIFT Workstation (download: sans.org/tools/sift-workstation)
- Python 3.12+ (pre-installed on SIFT)
- No API keys, no external services, no credits needed

### Step 1: Clone ChainSight
```bash
git clone https://github.com/Gideon145/chainsight.git ~/chainsight
```

### Step 2: Create evidence (or use your own)
```bash
cd /cases/demo
dd if=/dev/zero of=disk.dd bs=1M count=100
sudo mkfs.ext4 disk.dd
sudo mkdir -p /mnt/rd01
sudo mount -o loop disk.dd /mnt/rd01

# Plant test artifacts (simulated Emotet infection)
sudo mkdir -p /mnt/rd01/Users/jsmith/Downloads /mnt/rd01/ProgramData
echo "powershell.exe -enc JABwAGEAPQBOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAA7AA==" | sudo tee /mnt/rd01/Users/jsmith/Downloads/invoice.js > /dev/null
echo "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\WindowsUpdate=C:\ProgramData\payload.dll" | sudo tee /mnt/rd01/ProgramData/persistence.reg > /dev/null
echo "192.168.1.100:443 beacon interval=60 jitter=15" | sudo tee /mnt/rd01/ProgramData/config.bin > /dev/null

# Lock evidence as read-only
sudo chmod -R a+r /mnt/rd01
sudo umount /mnt/rd01
sudo mount -o ro,loop disk.dd /mnt/rd01
```

### Step 3: Run the orchestrator
```bash
python3 ~/chainsight/orchestrator.py --mount /mnt/rd01 --disk-image /cases/demo/disk.dd
```

### Expected output
- 4 agents execute sequentially (~5 seconds)
- 3 CRITICAL findings: encoded PowerShell, registry persistence, full attack chain
- 3 HIGH findings: C2 beacon config, phishing initial access, C2 confirmation
- 1 MEDIUM finding: temporal clustering (automated deployment)
- Forensic Confidence Score: 85.5 / 100 (Grade B)
- JSON report saved to `/cases/demo/reports/forensic_report.json`

### Step 4: View the report
```bash
cat /cases/demo/reports/forensic_report.json
```

---

## Option B: Run against your own evidence

```bash
# Mount your own disk image
sudo mkdir -p /mnt/rd01
sudo mount -o ro,loop /path/to/your/disk.dd /mnt/rd01

# Optionally provide a memory image
python3 ~/chainsight/orchestrator.py \
  --mount /mnt/rd01 \
  --disk-image /path/to/your/disk.dd \
  --memory /path/to/your/memory.mem
```

---

## Option C: Read the execution log

If you cannot run the SIFT VM, the full execution log with all agent outputs, cross-references, and score computation is at:

**[EXECUTION_LOG.md](EXECUTION_LOG.md)**

---

## What the orchestrator does

The Python orchestrator (`orchestrator.py`) runs 4 detection stages:

| Stage | Agent | Method | Output |
|-------|-------|--------|--------|
| 1. Collect | Disk | `find`, `cat`, `strings` — reads suspicious files | File contents |
| 2. Score | Rule Engine | Regex-based pattern matching against file contents | 0-100 confidence per rule |
| 3. Cross-Reference | Timeline | `find -printf` temporal analysis | Clustered creation times |
| 4. Hunt | Threat | Cross-agent correlation for attack chain detection | IOC confirmation |

**Key design decisions:**
- Pure rule-based detection — no AI API, no rate limits, deterministic results
- Same input = same output every time (verifiable by judges)
- Zero external dependencies beyond Python stdlib + SIFT tools
- All findings traceable to specific tool output lines

---

## Detection rules tested

| Rule | Pattern | Severity | Tested Against |
|------|---------|----------|---------------|
| Base64 PowerShell in Downloads `.js` | `powershell.*-enc` | CRITICAL | Emotet download cradle |
| Registry Run key in ProgramData `.reg` | `run.*windows` | CRITICAL | Emotet persistence |
| C2 beacon config `.bin` with IP:port | `\d+\.\d+\.\d+\.\d+:\d+` + `beacon` | HIGH | C2 setup pattern |
| Temporal clustering < 1s | File timestamps within 1 second | MEDIUM | Automated deployment |
| Cross-agent attack chain | Phishing + persistence + C2 confirmed | CRITICAL | Full kill chain |

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| Python not found | `python3` is available on SIFT; use `python3 --version` to verify |
| Permission denied reading files | Ensure `sudo chmod -R a+r /mnt/rd01` before remounting read-only |
| Mount point busy | `sudo umount /mnt/rd01` before remounting |
| No findings | Verify files were planted correctly: `find /mnt/rd01 -type f` |
