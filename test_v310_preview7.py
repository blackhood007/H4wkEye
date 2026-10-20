import importlib.util
from pathlib import Path
from xml.etree import ElementTree as ET
spec=importlib.util.spec_from_file_location('h4wkeye',Path(__file__).with_name('h4wkeye.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Fake: pass
Fake.root=ET.fromstring('''<config><devices><entry><device-group><entry name="DG"><devices><entry name="private-a"><vsys><entry name="private-v1"/></vsys></entry><entry name="private-b"><vsys><entry name="private-v2"/></vsys></entry></devices><post-rulebase><security><rules><entry name="r1"/><entry name="r2"><disabled>yes</disabled></entry><entry name="r3"><target><devices><entry name="private-a"/></devices></target></entry></rules></security></post-rulebase></entry></device-group></entry></devices></config>''')
c=m.panorama_candidate_mapping_preview(Fake())
a=m.panorama_applicability_preview(Fake())
r=m.panorama_reconciliation_preview(c,a,{'security':3,'nat':0,'decryption':0})
assert r['status']=='DIAGNOSTIC_ONLY',r
assert r['issues']=={},r['issues']
assert r['candidate_policy_references']==6 and r['unique_source_occurrences_referenced']==3
assert r['reused_assignment_references']==3
assert r['targeting_coverage']['explicit_target_eligible']==1
assert r['targeting_coverage']['explicit_target_excluded']==1
assert r['enablement_coverage']['disabled']==2
assert 'private-' not in str(r) and 'r1' not in str(r)
a['assignments'][0]['policy_counts']['security']['candidate']+=1
r2=m.panorama_reconciliation_preview(c,a,{'security':3})
assert r2['status']=='PARTIAL' and r2['issues'],r2
print('PASS: preview7 reconciliation, reuse, target coverage, tamper detection, privacy')