import importlib.util
from pathlib import Path
from xml.etree import ElementTree as ET
spec=importlib.util.spec_from_file_location('h4wkeye',Path(__file__).with_name('h4wkeye.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Fake: pass
Fake.root=ET.fromstring('''<config><devices><entry><device-group>
<entry name="Group-A"><devices><entry name="private-serial"><vsys><entry name="private-v1"/></vsys></entry><entry name="other-serial"><vsys><entry name="private-v2"/></vsys></entry></devices>
<post-rulebase><security><rules>
<entry name="open"/>
<entry name="disabled"><disabled>yes</disabled></entry>
<entry name="include"><target><devices><entry name="private-serial"><vsys><entry name="private-v1"/></vsys></entry></devices></target></entry>
<entry name="exclude"><target><negate>yes</negate><devices><entry name="private-serial"><vsys><entry name="private-v1"/></vsys></entry></devices></target></entry>
<entry name="unknown"><target><unsupported/></target></entry>
</rules></security></post-rulebase></entry>
</device-group></entry></devices></config>''')
r=m.panorama_applicability_preview(Fake())
assert r['assignment_count']==2 and r['issues']=={}
assert r['candidate_policy_references']==10 and r['unique_policy_source_occurrences_referenced']==5
assert r['effective_device_applicability']=='NOT_EVALUATED'
a=r['assignments'][0]['policy_counts']['security']; b=r['assignments'][1]['policy_counts']['security']
assert a['candidate']==5 and a['disabled']==1 and a['unresolved_applicability']==1
assert a['configuration_eligible_candidate']==2 and a['target_excluded_enabled']==1
assert b['configuration_eligible_candidate']==2 and b['target_excluded_enabled']==1
assert 'private-' not in str(r) and 'Group-A' not in str(r) and 'open' not in str(r)
Fake.root=ET.fromstring('''<config><devices><entry><device-group><entry name="G"><devices><entry name="serial"/></devices><post-rulebase><nat><rules><entry name="x"><target><devices><entry name="serial"><vsys><entry name="vsys1"/></vsys></entry></devices></target></entry></rules></nat></post-rulebase></entry></device-group></entry></devices></config>''')
r=m.panorama_applicability_preview(Fake())
a=r['assignments'][0]['policy_counts']['nat']
assert a['unresolved_applicability']==1 and a.get('configuration_eligible_candidate',0)==0
Fake.root=ET.fromstring('''<config><devices><entry><device-group><entry name="A"><devices><entry name="serial"><vsys><entry name="v1"/></vsys></entry></devices></entry><entry name="B"><devices><entry name="serial"><vsys><entry name="v1"/></vsys></entry></devices></entry></device-group></entry></devices></config>''')
r=m.panorama_applicability_preview(Fake())
assert r['issues']['CONFLICTING_VSYS_ASSIGNMENT']==1 and r['assignments'][0]['status']=='BLOCKED'
print('PASS: preview6 target inclusion/exclusion, enablement, source reuse, ambiguity, privacy, conflicts')