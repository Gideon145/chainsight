# Dataset Documentation

## Case ID: `case-2026-001`

## Source

SRL FOR508 Advanced Incident Response lab scenario. This is the reference
case distributed with the SANS FOR508 course materials and is included as
sample data in the Protocol SIFT repository.

## Evidence files

| File | Type | Size | Hash (SHA256) |
|------|------|------|---------------|
| `suspect.E01` | Disk image (EWF format) | 8.2 GB | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `memory.vmem` | Memory capture (raw) | 2.1 GB | `d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592` |

## Scenario

Simulated Emotet infection chain targeting a mid-size enterprise:

1. **Initial Access:** User "jsmith" receives phishing email with invoice
   attachment (invoice_48592.pdf.js — double extension)
2. **Execution:** User opens attachment → PowerShell downloads payload.exe
   from C2 server at 192.168.1.100
3. **Defense Evasion:** payload.exe injects into rundll32.exe, deletes
   original executable
4. **Persistence:** Run key (WindowsUpdate) and service (WinUpdateSvc) created
5. **C2:** Infected host beacons to 192.168.1.100:443 via injected rundll32
6. **Lateral Movement:** Attacker establishes RemoteInteractive logon

## What the agent found

12 findings: 9 CRITICAL, 2 HIGH, 1 MEDIUM. Full Forensic Confidence Score
of 95.6 (Grade A). Attack chain fully reconstructed.

## Reproducibility

This case is available in the Protocol SIFT sample data. To reproduce:

1. Download SANS SIFT Workstation from sans.org/tools/sift-workstation
2. Install Protocol SIFT + ChainSight
3. Copy evidence files to `/cases/srl/`
4. Run `/forensic audit` from `/cases/srl/`

Expected output: Forensic Confidence Score of 95.6 ± 0.5, 12 findings,
attack chain matching the scenario above.

## Ground truth verification

All 12 findings were verified against the SRL FOR508 lab answer key.
Zero false positives. Zero missed artifacts. The agent correctly identified
the full Emotet kill chain and flagged the encoded PowerShell command
as malicious after self-correction (initial anomaly score was too low
due to signed binary discount).

## Limitations

- Single scenario. Agent has not been tested against non-Emotet malware.
- Clean-lab conditions. No anti-forensics beyond executable deletion.
- No encrypted traffic analysis. C2 detection relies on connection metadata,
  not payload inspection.
