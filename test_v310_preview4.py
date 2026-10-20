import importlib.util
from pathlib import Path
from xml.etree import ElementTree as ET
p = Path(__file__).with_name('h4wkeye.py')
spec = importlib.util.spec_from_file_location('scanner', p)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
class Fake:
    root = ET.fromstring('<config><devices><entry><device-group>\n<entry name="Parent"><devices><entry name="secret-serial-1"><vsys><entry name="vsys1"/></vsys></entry></devices></entry>\n<entry name="Child"><parent-dg>Parent</parent-dg><devices><entry name="secret-serial-2"/></devices></entry>\n</device-group></entry></devices></config>')
r = m.panorama_membership_preview(Fake())
assert r['device_group_count'] == 2
assert r['unique_assigned_devices'] == 2
assert r['total_device_assignment_entries'] == 2
assert r['assignment_shapes'] == {'DEVICE_ONLY': 1, 'EXPLICIT_VSYS': 1}
assert r['device_groups'][0]['explicit_vsys_assignments'] == 1
assert 'secret-serial' not in str(r) and 'vsys1' not in str(r)
assert r['effective_device_applicability'] == 'NOT_EVALUATED'
Fake.root = ET.fromstring('<config><devices><entry><device-group><entry name="A"><devices><entry name="x"/></devices></entry><entry name="B"><devices><entry name="x"/></devices></entry></device-group></entry></devices></config>')
r = m.panorama_membership_preview(Fake())
assert r['issues']['DEVICE_IN_MULTIPLE_GROUPS'] == 1
assert r['status'] == 'PARTIAL'
print('PASS: preview4 membership, ambiguity, privacy')