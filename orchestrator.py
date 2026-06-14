#!/usr/bin/env python3
"""
ChainSight Orchestrator — Autonomous multi-agent forensic analysis.
Runs directly on SIFT Workstation. No Claude required.
Uses Google Gemini (free tier) for AI analysis.

Architecture: Custom Tool Server (hackathon Option 2 approach)
  - Typed forensic tool wrappers (not generic shell commands)
  - Agent physically cannot run destructive commands
  - Gemini analyzes structured tool output
  - Deterministic Forensic Confidence Score
"""

import os
import subprocess
import json
import sys
import argparse
from datetime import datetime
from pathlib import Path

# ── Configuration ──────────────────────────────────────────────────────────

CASE_DIR = Path(os.environ.get("CASE_DIR", "/cases/demo"))
MOUNT_POINT = Path(os.environ.get("MOUNT_POINT", "/mnt/rd01"))
MEMORY_IMAGE = os.environ.get("MEMORY_IMAGE", "")  # optional
GEMINI_KEY = os.environ.get("GEMINI_API_KEY", "")

# ── Forensic Confidence Score (deterministic, matches test_scoring.py) ─────

def compute_forensic_score(memory_conf, disk_conf, timeline_conf, threat_conf,
                           discrepancy_count=0, gap_count=0):
    base = (memory_conf * 25) + (disk_conf * 30) + (timeline_conf * 25) + (threat_conf * 20)
    disc_penalty = min(15, discrepancy_count * 5)
    gap_penalty = min(10, gap_count * 5)
    return max(0, min(100, base / 100 - disc_penalty - gap_penalty))

def grade(score):
    if score >= 90: return "A"
    if score >= 75: return "B"
    if score >= 60: return "C"
    if score >= 40: return "D"
    return "F"

# ── Tool wrappers (typed, safe — no shell injection possible) ──────────────

def run_tool(cmd: list[str], timeout: int = 60) -> dict:
    """Run a forensic tool safely. Returns stdout, stderr, returncode.
    Uses list form — no shell, no injection possible."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {"ok": r.returncode == 0, "stdout": r.stdout[:8000], "stderr": r.stderr[:2000], "rc": r.returncode}
    except subprocess.TimeoutExpired:
        return {"ok": False, "stdout": "", "stderr": "timeout", "rc": -1}
    except FileNotFoundError:
        return {"ok": False, "stdout": "", "stderr": f"tool not found: {cmd[0]}", "rc": -1}

def tool_fls(path: str) -> dict:
    return run_tool(["fls", "-r", "-p", path])

def tool_mmls(path: str) -> dict:
    return run_tool(["mmls", path])

def tool_icat(image: str, inode: str) -> dict:
    return run_tool(["icat", image, inode])

def tool_find(path: str, pattern: str) -> dict:
    return run_tool(["find", path, "-type", "f", "-name", pattern, "-printf", "%p %s\\n"])

def tool_find_suspicious(path: str) -> dict:
    """Find suspicious files: .js, .ps1, .exe, .dll, .bat, .vbs, .reg"""
    patterns = ["-name", "*.js", "-o", "-name", "*.ps1", "-o", "-name", "*.exe",
                "-o", "-name", "*.dll", "-o", "-name", "*.bat", "-o", "-name", "*.reg",
                "-o", "-name", "*.bin", "-o", "-name", "*.vbs"]
    cmd = ["find", path, "-type", "f"] + patterns + ["-printf", "%p\\n"]
    return run_tool(cmd, timeout=30)

def tool_strings(path: str, min_len: int = 4) -> dict:
    return run_tool(["strings", "-n", str(min_len), path])

def tool_cat(path: str) -> dict:
    return run_tool(["cat", path])

# ── Gemini AI analysis ────────────────────────────────────────────────────

def gemini_analyze(prompt: str, tool_outputs: dict) -> dict:
    """Send tool outputs to Gemini for forensic analysis."""
    if not GEMINI_KEY:
        return {"findings": [], "confidence": 0, "error": "No GEMINI_API_KEY set"}

    try:
        import google.generativeai as genai
        genai.configure(api_key=GEMINI_KEY)
        model = genai.GenerativeModel("gemini-2.5-flash-lite")

        context = f"""You are a forensic analyst. Analyze these tool outputs.

PROMPT: {prompt}

TOOL OUTPUTS:
{json.dumps(tool_outputs, indent=2)}

Return ONLY valid JSON with this schema:
{{
  "findings": [{{"id": "F-01", "artifact": "name", "severity": "CRITICAL|HIGH|MEDIUM|LOW", "description": "what was found", "evidence": "source line from tool output"}}],
  "confidence": 0-100,
  "summary": "one paragraph"
}}"""

        response = model.generate_content(context)
        text = response.text.strip()
        if text.startswith("```"):
            text = text.split("\n", 1)[1].rsplit("```", 1)[0]
        return json.loads(text)
    except Exception as e:
        return {"findings": [], "confidence": 0, "error": str(e)}

# ── Agent dispatchers ─────────────────────────────────────────────────────

def run_disk_agent(mount: str, image: str = "") -> dict:
    print("  [disk-agent] Starting disk forensics...")
    outputs = {}

    # Partition layout
    if image:
        outputs["mmls"] = tool_mmls(image)

    # Find suspicious files
    outputs["suspicious_files"] = tool_find_suspicious(mount)

    # Check for persistence artifacts
    reg_files = tool_find(mount, "*.reg")
    outputs["registry_files"] = reg_files

    # Check for scripts in user directories
    js_files = tool_find(mount, "*.js")
    outputs["js_files"] = js_files

    # Check for unusual binaries
    bin_files = tool_find(mount, "*.bin")
    outputs["bin_files"] = bin_files

    # Read any suspicious text files
    suspicious_contents = {}
    if reg_files["ok"]:
        for line in reg_files["stdout"].split("\n")[:3]:
            if line.strip():
                p = line.split()[0]
                suspicious_contents[p] = tool_cat(p)["stdout"][:500]

    if js_files["ok"]:
        for line in js_files["stdout"].split("\n")[:3]:
            if line.strip():
                p = line.split()[0]
                suspicious_contents[p] = tool_cat(p)["stdout"][:500]

    if bin_files["ok"]:
        for line in bin_files["stdout"].split("\n")[:3]:
            if line.strip():
                p = line.split()[0]
                suspicious_contents[p] = tool_strings(p)["stdout"][:500]

    outputs["file_contents"] = suspicious_contents

    # AI analysis
    prompt = "Analyze disk artifacts for: phishing files (.js), persistence mechanisms (.reg), C2 configs (.bin), suspicious executables. Flag anything malicious."
    ai = gemini_analyze(prompt, outputs)
    print(f"  [disk-agent] Found {len(ai.get('findings', []))} artifacts, confidence={ai.get('confidence', 0)}")
    return ai

def run_memory_agent() -> dict:
    print("  [memory-agent] Checking for memory image...")
    if not MEMORY_IMAGE or not Path(MEMORY_IMAGE).exists():
        print("  [memory-agent] No memory image available — skipping")
        return {"findings": [], "confidence": 0, "summary": "No memory image provided"}

    outputs = {}
    outputs["info"] = run_tool(["vol", "-f", MEMORY_IMAGE, "windows.info"])
    outputs["pslist"] = run_tool(["vol", "-f", MEMORY_IMAGE, "windows.pslist"])
    outputs["netscan"] = run_tool(["vol", "-f", MEMORY_IMAGE, "windows.netscan"])
    outputs["cmdline"] = run_tool(["vol", "-f", MEMORY_IMAGE, "windows.cmdline"])

    prompt = "Analyze memory for: hidden processes, injected code, C2 network connections, encoded PowerShell commands."
    ai = gemini_analyze(prompt, outputs)
    print(f"  [memory-agent] Found {len(ai.get('findings', []))} artifacts, confidence={ai.get('confidence', 0)}")
    return ai

def run_timeline_agent(mount: str) -> dict:
    print("  [timeline-agent] Building timeline from filesystem metadata...")
    outputs = {}

    # Use find to get file timestamps as a poor-man's timeline
    outputs["timeline"] = run_tool(["find", mount, "-type", "f", "-printf", "%T@ %p\\n", "-maxdepth", "5"])

    prompt = "Build a timeline of file creation/modification. Identify suspicious temporal patterns."
    ai = gemini_analyze(prompt, outputs)
    print(f"  [timeline-agent] Found {len(ai.get('findings', []))} temporal patterns, confidence={ai.get('confidence', 0)}")
    return ai

def run_threat_agent(mount: str) -> dict:
    print("  [threat-agent] Hunting for IOCs and attack patterns...")
    outputs = {}

    # Search for known-bad patterns: base64, C2 IPs, persistence keys
    outputs["base64_strings"] = run_tool(["grep", "-rl", "AAAA|Q3J5|powershell|cmd\\.exe|rundll32|HKLM|CurrentVersion\\\\Run|beacon|payload", mount])

    # Read all suspicious files for IOC matching
    ioc_matches = tool_find_suspicious(mount)
    outputs["ioc_targets"] = ioc_matches

    prompt = "Hunt for threats: base64-encoded commands, C2 beacon configs, persistence registry keys, known malware IOCs. Cross-reference with disk findings."
    ai = gemini_analyze(prompt, outputs)
    print(f"  [threat-agent] Found {len(ai.get('findings', []))} threat indicators, confidence={ai.get('confidence', 0)}")
    return ai

# ── Cross-reference engine ────────────────────────────────────────────────

def cross_reference(findings_by_agent: dict) -> tuple[int, int]:
    """Count discrepancies and gaps across agents."""
    all_findings = []
    for agent, data in findings_by_agent.items():
        for f in data.get("findings", []):
            all_findings.append({**f, "source_agent": agent})

    discrepancies = 0
    gaps = 0

    # Simple cross-reference: check if any agent found nothing
    for agent, data in findings_by_agent.items():
        if not data.get("findings"):
            gaps += 1

    # Check for conflicting severity between agents
    severities = {}
    for f in all_findings:
        key = f.get("artifact", f.get("id", ""))
        if key in severities and severities[key] != f.get("severity"):
            discrepancies += 1
        severities[key] = f.get("severity")

    return discrepancies, gaps

# ── Main orchestrator ────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="ChainSight Autonomous Forensic Orchestrator")
    parser.add_argument("--case", default=str(CASE_DIR), help="Case directory")
    parser.add_argument("--mount", default=str(MOUNT_POINT), help="Mount point for disk evidence")
    parser.add_argument("--memory", default=MEMORY_IMAGE, help="Memory image path")
    parser.add_argument("--disk-image", default="", help="Raw disk image path (for mmls)")
    args = parser.parse_args()

    global MEMORY_IMAGE
    MEMORY_IMAGE = args.memory

    print("=" * 60)
    print(f"  ChainSight Autonomous Forensic Orchestrator")
    print(f"  Time: {datetime.now().isoformat()}")
    print(f"  Case: {args.case}")
    print(f"  Mount: {args.mount}")
    print(f"  Memory: {args.memory or 'not provided'}")
    print(f"  AI: Gemini 2.5 Flash Lite (free tier)")
    print("=" * 60)

    if not GEMINI_KEY:
        print("\n⚠️  GEMINI_API_KEY not set. Export it first:")
        print("   export GEMINI_API_KEY=your-key-here")
        sys.exit(1)

    # Dispatch all 4 agents in parallel (sequentially for reliability)
    print("\n── Stage 1: Dispatch ──")
    disk_results = run_disk_agent(args.mount, args.disk_image)
    memory_results = run_memory_agent()
    timeline_results = run_timeline_agent(args.mount)
    threat_results = run_threat_agent(args.mount)

    # Cross-reference
    print("\n── Stage 2: Cross-Reference ──")
    agents = {
        "memory": memory_results,
        "disk": disk_results,
        "timeline": timeline_results,
        "threat": threat_results,
    }
    discrepancies, gaps = cross_reference(agents)
    print(f"  Discrepancies: {discrepancies}, Gaps: {gaps}")

    # Compute Forensic Confidence Score
    print("\n── Stage 3: Forensic Confidence Score ──")
    score = compute_forensic_score(
        memory_results.get("confidence", 0),
        disk_results.get("confidence", 0),
        timeline_results.get("confidence", 0),
        threat_results.get("confidence", 0),
        discrepancies, gaps,
    )
    print(f"  Score: {score:.1f} / 100 — Grade {grade(score)}")

    # Consolidate all findings
    all_findings = []
    for agent, data in agents.items():
        for f in data.get("findings", []):
            all_findings.append({**f, "source_agent": agent})

    # Generate report
    report = {
        "timestamp": datetime.now().isoformat(),
        "case": args.case,
        "mount_point": args.mount,
        "forensic_confidence_score": round(score, 1),
        "grade": grade(score),
        "total_findings": len(all_findings),
        "findings_by_severity": {
            "CRITICAL": sum(1 for f in all_findings if f.get("severity") == "CRITICAL"),
            "HIGH": sum(1 for f in all_findings if f.get("severity") == "HIGH"),
            "MEDIUM": sum(1 for f in all_findings if f.get("severity") == "MEDIUM"),
            "LOW": sum(1 for f in all_findings if f.get("severity") == "LOW"),
        },
        "discrepancies": discrepancies,
        "gaps": gaps,
        "findings": all_findings,
        "agent_summaries": {
            agent: data.get("summary", "") for agent, data in agents.items()
        },
    }

    # Save report
    report_path = Path(args.case) / "reports" / "forensic_report.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)

    # Print summary
    print("\n" + "=" * 60)
    print("  FORENSIC AUDIT COMPLETE")
    print("=" * 60)
    print(f"  Confidence Score: {score:.1f}/100 (Grade {grade(score)})")
    print(f"  Total Findings:   {len(all_findings)}")
    print(f"    CRITICAL: {report['findings_by_severity']['CRITICAL']}")
    print(f"    HIGH:     {report['findings_by_severity']['HIGH']}")
    print(f"    MEDIUM:   {report['findings_by_severity']['MEDIUM']}")
    print(f"    LOW:      {report['findings_by_severity']['LOW']}")
    print(f"  Report saved: {report_path}")
    print("=" * 60)

    return 0


if __name__ == "__main__":
    sys.exit(main())
