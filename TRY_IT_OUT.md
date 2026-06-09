# Try-It-Out Instructions — FIND EVIL

Judges can run FIND EVIL against the provided sample case data or their
own evidence files.

---

## Option A: Quickest path (SIFT VM + Protocol SIFT + FIND EVIL)

### Prerequisites
- SANS SIFT Workstation (download: sans.org/tools/sift-workstation)
- Anthropic API key
- 8 GB RAM minimum (16 GB recommended for memory analysis)

### Step 1: Install Protocol SIFT
```bash
curl -fsSL https://raw.githubusercontent.com/teamdfir/protocol-sift/main/install.sh | bash
```

### Step 2: Install FIND EVIL
```bash
git clone https://github.com/Gideon145/find-evil.git ~/find-evil
cp ~/.claude/CLAUDE.md ~/.claude/CLAUDE.md.protocol-sift.bak
cp ~/find-evil/CLAUDE.md ~/.claude/CLAUDE.md
cp -r ~/find-evil/skills/* ~/.claude/skills/
```

### Step 3: Prepare case directory
```bash
export CASE=find-evil-demo
mkdir -p /cases/${CASE}/{analysis,exports,reports}
cp ~/.claude/case-templates/CLAUDE.md /cases/${CASE}/CLAUDE.md
cp ~/.claude/analysis-scripts/generate_pdf_report.py /cases/${CASE}/analysis/
```

### Step 4: Mount evidence (with provided sample or your own)
```bash
sudo mkdir -p /mnt/ewf_rd01 /mnt/rd01
sudo ewfmount /cases/${CASE}/suspect.E01 /mnt/ewf_rd01
OFFSET=$(sudo mmls /mnt/ewf_rd01/ewf1 | awk '/NTFS/{print $3; exit}')
sudo mount -o ro,loop,noatime,offset=$((OFFSET*512)) /mnt/ewf_rd01/ewf1 /mnt/rd01
```

### Step 5: Run the agent
```bash
cd /cases/${CASE}
claude

# Inside Claude Code:
/forensic audit
```

### Expected output
- 4 agents execute in parallel (~90 seconds)
- Structured JSON output from each agent
- Forensic Confidence Score (0-100 with grade)
- PDF report in `./reports/`
- Session audit log in `./analysis/forensic_audit.log`

---

## Option B: Read the execution log

If you cannot run the SIFT VM, the full execution log with all agent
outputs, confidence score computation, and self-correction trace is at:

**[EXECUTION_LOG.md](EXECUTION_LOG.md)**

This log shows every tool invocation, every finding, and the complete
attack chain reconstruction — exactly what a live run produces.

---

## What to look for (self-correction sequence)

The key moment to verify is the self-correction on the PowerShell finding:

1. Agent flags `powershell.exe` as LOW confidence (anomaly score 15)
   — Microsoft-signed binary, scoring formula discounts it
2. Doubt-driven review triggers: checks parent process (cmd.exe from
   explorer), child process (payload.exe, known IOC), user context
   (jsmith, phishing victim)
3. Anomaly score revised from 15 → 75 (LOW → HIGH confidence)
4. This sequence is documented in EXECUTION_LOG.md at timestamp 14:04:05

This demonstrates the agent recognizing its own mistake, cross-referencing
context, and correcting — the core behavior the hackathon evaluates.

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| Claude Code not installed | `npm install -g @anthropic-ai/claude-code` |
| WeasyPrint PDF fails | `pip3 install weasyprint` |
| Evidence mount fails | Verify EWF image integrity: `ewfverify suspect.E01` |
| Agent claims tools not found | Protocol SIFT installer adds tools to PATH; re-run `install.sh` |
| skills not loading | Verify files in `~/.claude/skills/` with correct subdirectory names |
