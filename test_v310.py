import importlib.util
from pathlib import Path
from xml.etree import ElementTree as ET
p=Path(__file__).with_name('h4wkeye.py')
spec=importlib.util.spec_from_file_location('scanner',p)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Fake:
    def __init__(self,xml):self.root=ET.fromstring(xml)
xml='''<config><shared><pre-rulebase><security><rules><entry name="s"/></rules></security></pre-rulebase></shared><devices><entry name="localhost"><device-group><entry name="parent"><pre-rulebase><security><rules><entry name="p"/></rules></security></pre-rulebase></entry><entry name="child"><parent-dg>parent</parent-dg><post-rulebase><nat><rules><entry name="n"/></rules></nat></post-rulebase></entry></device-group></entry></devices></config>'''
r=m.panorama_inheritance_preview(Fake(xml))
assert r['device_group_count']==2
child=next(x for x in r['device_groups'] if len(x['ancestor_chain'])==2)
assert child['candidate_policy_counts']=={'security':2,'nat':1,'decryption':0},child
assert [x['source'] for x in child['composition']]==['shared_pre','dg_pre','dg_pre','dg_post','dg_post','shared_post']
assert 'parent' not in str(r) and 'child' not in str(r)
cycle=xml.replace('<parent-dg>parent</parent-dg>','<parent-dg>parent</parent-dg>').replace('<entry name="parent"><pre-rulebase>','<entry name="parent"><parent-dg>child</parent-dg><pre-rulebase>')
r=m.panorama_inheritance_preview(Fake(cycle))
assert 'PARENT_CYCLE' in r['problems']
print('PASS: hierarchy composition, privacy, ordering, cycle detection')