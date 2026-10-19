import importlib.util
from pathlib import Path
from xml.etree import ElementTree as ET
spec = importlib.util.spec_from_file_location('scanner', Path(__file__).with_name('h4wkeye.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
class Fake: pass
Fake.root = ET.fromstring('''<config><shared><pre-rulebase><security><rules><entry name="secret-shared"/></rules></security></pre-rulebase></shared><devices><entry><device-group>
<entry name="Parent"><pre-rulebase><security><rules><entry name="p1"/></rules></security></pre-rulebase><post-rulebase><security><rules><entry name="p2"><disabled>yes</disabled></entry></rules></security></post-rulebase></entry>
<entry name="Child"><parent-dg>Parent</parent-dg><devices><entry name="secret-device"><vsys><entry name="secret-vsys"/></vsys></entry></devices><pre-rulebase><security><rules><entry name="c1"><target><negate>no</negate></target></entry></rules></security></pre-rulebase><post-rulebase><security><rules><entry name="c2"><target><devices><entry name="another-device"/></devices></target></entry></rules></security></post-rulebase></entry>
</device-group></entry></devices></config>''')
r=m.panorama_candidate_mapping_preview(Fake())
assert r['assignment_count']==1 and r['issues']=={}
a=r['assignments'][0]
assert a['status']=='CANDIDATE_ONLY' and a['ancestor_chain']==['DG-002','DG-001']
assert [x['counts']['security'] for x in a['ordered_sources']]==[1,1,1,1,1,0]
c=a['policy_counts']['security']
assert c['candidate']==5 and c['disabled']==1 and c['enabled_or_unspecified']==4
assert c['explicit_target_requires_resolution']==1 and c['no_explicit_target']==4
assert 'secret-' not in str(r) and 'another-device' not in str(r)
Fake.root = ET.fromstring('''<config><devices><entry><device-group><entry name="A"><devices><entry name="serial"><vsys><entry name="v1"/></vsys></entry></devices></entry><entry name="B"><devices><entry name="serial"><vsys><entry name="v2"/></vsys></entry></devices></entry></device-group></entry></devices></config>''')
r=m.panorama_candidate_mapping_preview(Fake())
assert r['assignment_count']==2 and not r['issues']
Fake.root = ET.fromstring('''<config><devices><entry><device-group><entry name="A"><devices><entry name="serial"><vsys><entry name="v1"/></vsys></entry></devices></entry><entry name="B"><devices><entry name="serial"><vsys><entry name="v1"/></vsys></entry></devices></entry></device-group></entry></devices></config>''')
r=m.panorama_candidate_mapping_preview(Fake())
assert r['issues']['CONFLICTING_VSYS_ASSIGNMENT']==1 and r['assignments'][0]['status']=='BLOCKED'
print('PASS: preview5 inheritance, disabled, targets, VSYS split/conflict, privacy')