import json, subprocess, sys, tempfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SENTINELS=["SUPER_SECRET_PSK_123"]

def run(mode):
    with tempfile.TemporaryDirectory() as td:
        p=subprocess.run([sys.executable,str(ROOT/"h4wkeye.py"),str(ROOT/"samples/synthetic-safe-config.xml"),"--privacy",mode,"--output",td],capture_output=True,text=True)
        assert p.returncode==0, p.stderr
        combined=p.stdout+p.stderr
        for f in Path(td).iterdir(): combined += f.read_text(errors="ignore")
        for secret in SENTINELS: assert secret not in combined
        if mode=="strict":
            assert "10.10.10.10" not in combined
            assert "SYNTHETIC-RULE" not in combined

if __name__=="__main__":
    run("standard")
    run("strict")
    print("privacy tests passed")
