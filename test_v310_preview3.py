import importlib.util
from pathlib import Path
from xml.etree import ElementTree as ET
p = Path(__file__).with_name('h4wkeye.py')
spec = importlib.util.spec_from_file_location('scanner', p)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
def classify(inner):
    return m.classify_panorama_rule_target(ET.fromstring('<entry name="test">'+inner+'</entry>'))
assert classify('') == 'NO_EXPLICIT_TARGET'
assert classify('<target/>') == 'NO_EXPLICIT_TARGET'
assert classify('<target><negate>no</negate></target>') == 'NO_EXPLICIT_TARGET'
assert classify('<target><negate>NO</negate></target>') == 'NO_EXPLICIT_TARGET'
assert classify('<target><negate>yes</negate></target>') == 'UNKNOWN_TARGET_SHAPE'
assert classify('<target><negate>maybe</negate></target>') == 'UNKNOWN_TARGET_SHAPE'
assert classify('<target><devices/></target>') == 'NO_EXPLICIT_TARGET'
assert classify('<target><devices><entry name="serial"/></devices></target>') == 'EXPLICIT_TARGET_INCLUSION'
assert classify('<target><negate>yes</negate><devices><entry name="serial"/></devices></target>') == 'EXPLICIT_TARGET_EXCLUSION'
assert classify('<target><devices><entry name="serial"><vsys><entry name="vsys1"/></vsys></entry></devices></target>') == 'EXPLICIT_TARGET_INCLUSION'
assert classify('<target><devices><bad/></devices></target>') == 'UNKNOWN_TARGET_SHAPE'
assert classify('<target><devices><entry/></devices></target>') == 'UNKNOWN_TARGET_SHAPE'
assert classify('<target><devices><entry name="serial"><weird/></entry></devices></target>') == 'UNKNOWN_TARGET_SHAPE'
assert classify('<target><unexpected/></target>') == 'UNKNOWN_TARGET_SHAPE'
assert classify('<target><negate>no</negate><negate>no</negate></target>') == 'UNKNOWN_TARGET_SHAPE'
class Fake:
    root = ET.fromstring('<config><shared><pre-rulebase><security><rules>' +
        ''.join('<entry name="x%d"><target><negate>no</negate></target></entry>' % i for i in range(26)) +
        '<entry name="off"><disabled>yes</disabled></entry>' +
        '</rules></security></pre-rulebase></shared></config>')
r = m.panorama_targeting_preview(Fake())
assert r['raw_rules_visited'] == 27
assert r['targeting'] == {'NO_EXPLICIT_TARGET': 27}, r
assert r['enablement']['DISABLED'] == 1
assert r['effective_device_applicability'] == 'NOT_EVALUATED'
print('PASS: preview3 targeting shape, enablement, privacy-safe aggregate')