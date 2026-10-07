#!/usr/bin/env python3
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory() as td:
    out = Path(td)
    r = subprocess.run([
        sys.executable, str(ROOT/"h4wkeye.py"),
        str(ROOT/"samples/synthetic-safe-config.xml"),
        "--baseline", str(ROOT/"baseline.json"),
        "--privacy", "strict", "--output", str(out)
    ], text=True, capture_output=True)
    assert r.returncode == 0, r.stderr
    pdf = out/"H4wkEye-report.pdf"
    assert pdf.is_file() and pdf.stat().st_size > 1000
    if shutil.which("pdftotext"):
        textfile = out/"report.txt"
        subprocess.run(["pdftotext", str(pdf), str(textfile)], check=True)
        text = textfile.read_text(encoding="utf-8", errors="ignore")
        assert "SUPER_SECRET_PSK_123" not in text
        assert "10.10.10.10" not in text
        assert "Allow-Everything-Test" not in text
        assert "PA-FW-001" in text
print("PDF regression: PASS")
