import importlib.util
from pathlib import Path
from xml.etree import ElementTree as ET
p=Path(__file__).with_name('h4wkeye.py')
spec=importlib.util.spec_from_file_location('scanner',p)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Fake:
    def __init__(self,xml):self.root=ET.fromstring(xml)
xml='''<config><shared><pre-rulebase><security><rules>
<entry name="plain"/><entry name="off"><disabled>yes</disabled></entry>
<entry name="targeted"><target><devices><entry name="secretserial"/></devices></target></entry>
<entry name="excluded"><target><negate>yes</negate><devices><entry name="anothersecret"/></devices></target></entry>
</rules></security></pre-rulebase></shared>
<devices><entry name="localhost"><device-group><entry name="parent"><pre-rulebase><nat><rules><entry name="n"/></rules></nat></pre-rulebase></entry><entry name="child"><parent-dg>parent</parent-dg></entry></device-group></entry></devices></config>'''
r=m.panorama_targeting_preview(Fake(xml))
assert r['raw_rules_visited']==5,r
assert r['targeting']['NO_EXPLICIT_TARGET']==3,r
assert r['targeting']['EXPLICIT_TARGET_INCLUSION']==1,r
assert r['targeting']['EXPLICIT_TARGET_EXCLUSION']==1,r
assert r['enablement']['DISABLED']==1,r
assert r['effective_device_applicability']=='NOT_EVALUATED'
assert 'secretserial' not in str(r) and 'anothersecret' not in str(r)
print('PASS: preview2 targeting, disabled, privacy, raw-rule counts')