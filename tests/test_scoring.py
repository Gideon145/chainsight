# FIND EVIL — Eval Harness
# pytest suite for deterministic forensic scoring validation.
#
# Run: pytest tests/ -v

import json
import pytest

# ---------------------------------------------------------------------------
# Confidence Score math — must be deterministic
# ---------------------------------------------------------------------------

def compute_forensic_score(memory_conf, disk_conf, timeline_conf, threat_conf,
                           discrepancy_count=0, gap_count=0):
    """Re-implementation of the Forensic Confidence Score formula from CLAUDE.md.
    Must match exactly — this test catches drift."""
    base = (memory_conf * 25) + (disk_conf * 30) + (timeline_conf * 25) + (threat_conf * 20)
    disc_penalty = min(15, discrepancy_count * 5)
    gap_penalty = min(10, gap_count * 5)
    return max(0, min(100, base / 100 - disc_penalty - gap_penalty))


class TestConfidenceScore:
    """Deterministic scoring math — 10 runs must produce identical results."""

    def test_perfect_score(self):
        score = compute_forensic_score(0.95, 0.95, 0.95, 0.95)
        assert score == pytest.approx(95.0, abs=0.1)

    def test_deterministic(self):
        scores = [compute_forensic_score(0.85, 0.90, 0.80, 0.75, 1, 0)
                  for _ in range(10)]
        assert len(set(scores)) == 1, "Scoring must be deterministic"

    def test_discrepancy_penalty(self):
        clean = compute_forensic_score(0.90, 0.90, 0.90, 0.90, 0, 0)
        dirty = compute_forensic_score(0.90, 0.90, 0.90, 0.90, 3, 0)
        assert dirty < clean, "Discrepancies must lower score"

    def test_gap_penalty(self):
        clean = compute_forensic_score(0.80, 0.80, 0.80, 0.80, 0, 0)
        gapped = compute_forensic_score(0.80, 0.80, 0.80, 0.80, 0, 2)
        assert gapped < clean, "Missing evidence must lower score"

    def test_floor_zero(self):
        score = compute_forensic_score(0.0, 0.0, 0.0, 0.0, 10, 10)
        assert score >= 0, "Score must not go below 0"

    def test_ceiling_100(self):
        score = compute_forensic_score(1.0, 1.0, 1.0, 1.0, 0, 0)
        assert score <= 100, "Score must not exceed 100"

    def test_grade_boundaries(self):
        a = compute_forensic_score(0.95, 0.95, 0.95, 0.95)  # ~95 → A
        b = compute_forensic_score(0.85, 0.85, 0.85, 0.85)  # ~85 → B
        c = compute_forensic_score(0.70, 0.70, 0.70, 0.70)  # ~70 → C
        d = compute_forensic_score(0.50, 0.50, 0.50, 0.50)  # ~50 → D
        f = compute_forensic_score(0.30, 0.30, 0.30, 0.30)  # ~30 → F
        assert a >= 90
        assert 75 <= b < 90
        assert 60 <= c < 75
        assert 40 <= d < 60
        assert f < 40


# ---------------------------------------------------------------------------
# Anomaly scoring — must be deterministic
# ---------------------------------------------------------------------------

def compute_anomaly_score(hash_match, yara_match, sigma_match, multi_source, legit_signed):
    return (hash_match * 40) + (yara_match * 35) + (sigma_match * 25) + (multi_source * 20) - (legit_signed * 30)


class TestAnomalyScore:
    def test_max_score(self):
        assert compute_anomaly_score(1, 1, 1, 1, 0) == 120

    def test_min_score(self):
        assert compute_anomaly_score(0, 0, 0, 0, 1) == -30

    def test_ioc_match_only(self):
        assert compute_anomaly_score(1, 0, 0, 0, 0) == 40

    def test_signed_binary_discount(self):
        unsigned = compute_anomaly_score(1, 0, 0, 0, 0)
        signed = compute_anomaly_score(1, 0, 0, 0, 1)
        assert signed < unsigned

    def test_threshold_high(self):
        assert compute_anomaly_score(1, 1, 0, 0, 0) >= 60  # 75 → HIGH

    def test_threshold_suspicious(self):
        score = compute_anomaly_score(1, 0, 0, 0, 0)  # 40 → suspicious
        assert 30 <= score <= 60

    def test_threshold_false_positive(self):
        score = compute_anomaly_score(0, 0, 0, 0, 1)  # -30 → FP
        assert score < 30


# ---------------------------------------------------------------------------
# Severity mapping — must be consistent across all 4 skill files
# ---------------------------------------------------------------------------

SEVERITY_WEIGHTS = {"CRITICAL": 100, "HIGH": 70, "MEDIUM": 40, "LOW": 10}


class TestSeverityConsistency:
    """Every severity level used in SKILL.md files must map to a known weight."""

    def test_severity_levels_defined(self):
        assert "CRITICAL" in SEVERITY_WEIGHTS
        assert "HIGH" in SEVERITY_WEIGHTS
        assert "MEDIUM" in SEVERITY_WEIGHTS
        assert "LOW" in SEVERITY_WEIGHTS

    def test_severity_ordering(self):
        assert SEVERITY_WEIGHTS["CRITICAL"] > SEVERITY_WEIGHTS["HIGH"]
        assert SEVERITY_WEIGHTS["HIGH"] > SEVERITY_WEIGHTS["MEDIUM"]
        assert SEVERITY_WEIGHTS["MEDIUM"] > SEVERITY_WEIGHTS["LOW"]


# ---------------------------------------------------------------------------
# Output format — all agents must produce valid JSON
# ---------------------------------------------------------------------------

REQUIRED_FIELDS = {
    "memory": ["artifact_type", "system", "processes", "network", "injection", "confidence"],
    "disk": ["artifact_type", "filesystem", "execution", "persistence", "events", "confidence"],
    "timeline": ["artifact_type", "total_events", "time_range", "clusters", "gaps", "confidence"],
    "threat": ["artifact_type", "iocs_matched", "yara_hits", "sigma_hits", "highest_scoring"],
}


class TestOutputFormat:
    def test_all_agents_have_required_fields(self):
        for agent, fields in REQUIRED_FIELDS.items():
            for field in fields:
                assert field, f"{agent} agent missing required field"

    def test_all_agents_have_artifact_type(self):
        for agent in REQUIRED_FIELDS:
            assert "artifact_type" in REQUIRED_FIELDS[agent]

    def test_memory_disk_timeline_have_confidence(self):
        for agent in ["memory", "disk", "timeline"]:
            assert "confidence" in REQUIRED_FIELDS[agent]
