"""Synthetic offline regression checks; no customer configuration included."""
import importlib.util
import json
import tempfile
from pathlib import Path
from xml.etree import ElementTree as ET

script = Path(__file__).with_name('h4wkeye.py')
spec = importlib.util.spec_from_file_location('h4wkeye_3010', script)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

class Fake:
    def __init__(self, xml, findings=None):
        self.root = ET.fromstring(xml)
        self.findings = findings or []
        self.inventory = mod.Counter()

base = '''<config><devices><entry name="fw"><deviceconfig><system/></deviceconfig><network><interface><ethernet><entry name="ethernet1/1"/></ethernet></interface><ike><gateway><entry name="test-gw"/></gateway></ike></network><vsys><entry name="vsys1"><rulebase><security><rules/></security></rulebase></entry></vsys></entry></devices></config>'''
f = Fake(base)
r = mod.standalone_coverage_inventory(f)
assert r['configuration_entry_counts']['ike_gateways'] == 1, r
assert r['local_policy_status'] == 'NO_LOCAL_RULES', r
assert r['local_policy_entries']['security'] == 0, r
assert r['effective_policy_status'] == 'NOT_DETERMINED', r
assert 'test-gw' not in str(r) and 'ethernet1/1' not in str(r), r
assert mod.detect_coverage(f)[0] == 'PARTIAL'
f.findings = [{'severity':'LOW'}]
assert 'zero findings' not in mod.detect_coverage(f)[1]

with tempfile.TemporaryDirectory() as d:
    d = Path(d)
    empty = d/'empty.xml'
    empty.write_bytes(b'')
    try:
        mod.Scanner(empty, mod.DEFAULT_BASELINE)
    except ValueError as e:
        assert str(e).startswith('EMPTY_FILE:'), e
    else:
        raise AssertionError('empty input accepted')

    sample = d/'sample.xml'
    sample.write_text(base)
    output = d/'out'
    result = mod.scan_one(sample, output, mod.DEFAULT_BASELINE, 'standard', {'csv'})
    assert result['status'] == 'PARTIAL', result
    assert (output/'H4wkEye-report.csv').exists()
    assert not (output/'H4wkEye-report.pdf').exists()
    assert not (output/'H4wkEye-report.html').exists()
    assert not (output/'H4wkEye-report.json').exists()
    cov = json.loads((output/'H4wkEye-coverage.json').read_text())
    assert cov['configuration_coverage']['local_policy_status'] == 'NO_LOCAL_RULES'

    bad = Fake('<config><adRedactedess/></config>')
    assert mod.standalone_coverage_inventory(bad)['structure_warnings']['redaction_like_element_names'] == 1

print('PASS: empty input, standalone inventory, findings note, privacy, CSV-only, coverage JSON, redaction warning')

# Batch combined CSV: generated independently of per-file CSV selection.
import subprocess
import sys
import csv
with tempfile.TemporaryDirectory() as d:
    root = Path(d)
    inputs = root / 'inputs'
    inputs.mkdir()
    (inputs / 'a.xml').write_text(base)
    (inputs / 'b.xml').write_text(base)
    (inputs / 'empty.xml').write_bytes(b'')
    cmd = [sys.executable, str(script), '--input-dir', str(inputs),
           '--output-dir', str(root / 'reports'), '--format', 'html', '--combined-csv']
    completed = subprocess.run(cmd, capture_output=True, text=True)
    assert completed.returncode == 1, completed.stderr
    batch = next((root / 'reports').iterdir())
    combined = batch / 'combined-findings.csv'
    assert combined.exists()
    with combined.open(encoding='utf-8-sig', newline='') as fh:
        reader = csv.DictReader(fh)
        assert 'configuration' in reader.fieldnames
        assert 'scan_status' in reader.fieldnames
        assert list(reader) == []  # no findings in synthetic empty-rulebase fixtures
    assert len(list(batch.glob('*/H4wkEye-report.html'))) == 2
    assert not list(batch.glob('*/H4wkEye-report.csv'))
    summary = json.loads((batch / 'batch-summary.json').read_text())
    assert summary['combined_csv'] == 'combined-findings.csv'
    assert summary['status_counts']['FAILED'] == 1
    assert summary['status_counts']['PARTIAL'] == 2
    invalid = subprocess.run([sys.executable, str(script), str(inputs / 'a.xml'), '--combined-csv'], capture_output=True, text=True)
    assert invalid.returncode == 2 and 'requires --input-dir' in invalid.stderr
print('PASS: combined CSV batch, independent format selection, empty findings header, failed-file isolation, single-file rejection')