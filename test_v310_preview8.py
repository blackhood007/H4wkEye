import csv
import importlib.util
import tempfile
from pathlib import Path

from pypdf import PdfReader

spec = importlib.util.spec_from_file_location('h4wkeye', Path(__file__).with_name('h4wkeye.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

base = {
    "severity": "HIGH", "confidence": "CONFIRMED", "status": "CONFIGURATION",
    "section": "Firewall Rules", "title": "Overly permissive security rule",
    "scope": "DG-Alpha", "risk_score": 9,
    "description": "The rule permits broad traffic.",
    "remediation": "Restrict sources, destinations and services.",
    "source_zones": "trust", "source_objects": "src_obj", "destination_zones": "untrust",
    "destination_objects": "dst_obj", "applications": "any", "services": "any",
    "resolved_sources": "10.10.1.0/24", "resolved_destinations": "203.0.113.10",
    "evidence": "Source and destination are broad.",
}
rows = []
for i, (obj, src, dst, scope) in enumerate([
    ("Rule-A", "10.10.1.0/24", "203.0.113.10", "DG-Alpha"),
    ("Rule-B", "10.10.2.0/24", "203.0.113.20", "DG-Alpha"),
    ("Rule-C", "10.10.3.0/24", "203.0.113.30", "DG-Beta"),
], 1):
    rows.append({**base, "finding_id": f"PA-FW-{i:03d}", "object": obj,
                 "resolved_sources": src, "resolved_destinations": dst, "scope": scope})
# Similar non-rule findings must not merge.
rows.append({**base, "finding_id": "PA-REV-001", "section": "Manual Review", "object": "manual-item"})

groups = m.consolidate_findings(rows)
assert len(groups) == 3, len(groups)
assert sorted(g["affected_count"] for g in groups) == [1, 1, 2]
main = next(g for g in groups if g["affected_count"] == 2)
assert {r["object"] for r in main["affected_rules"]} == {"Rule-A", "Rule-B"}
assert {r["resolved_sources"] for r in main["affected_rules"]} == {"10.10.1.0/24", "10.10.2.0/24"}
flat = m.evidence_rows(groups)
assert len(flat) == 4

with tempfile.TemporaryDirectory() as td:
    td = Path(td)
    summary = td / "summary.csv"
    detail = td / "detail.csv"
    pdf = td / "report.pdf"
    m.write_csv(summary, groups)
    m.write_evidence_csv(detail, groups)
    with summary.open(encoding="utf-8-sig", newline="") as f:
        assert len(list(csv.DictReader(f))) == 3
    with detail.open(encoding="utf-8-sig", newline="") as f:
        detail_rows = list(csv.DictReader(f))
    assert len(detail_rows) == 4
    assert {r["resolved_sources"] for r in detail_rows if r["object"] in ("Rule-A", "Rule-B")} == {"10.10.1.0/24", "10.10.2.0/24"}

    data = {
        "metadata": {"configuration": "synthetic.xml", "scanner_version": m.VERSION,
                     "generated_at": "2026-10-19", "privacy_mode": "standard",
                     "detected_finding_count": len(rows)},
        "findings": groups, "inventory": {}, "rule_statistics": {}, "vpn_inventory": [],
    }
    m.write_pdf(pdf, data)
    text = "\n".join(page.extract_text() or "" for page in PdfReader(str(pdf)).pages)
    for expected in ("Rule-A", "Rule-B", "10.10.1.0/24", "10.10.2.0/24",
                     "203.0.113.10", "203.0.113.20", "Affected Rules and Complete Technical Evidence"):
        assert expected in text, expected
    assert pdf.stat().st_size > 1000

print("PASS: Preview 8 consolidation preserves distinct scopes, all per-rule IP evidence, summary/detail CSV, and fully expanded PDF")