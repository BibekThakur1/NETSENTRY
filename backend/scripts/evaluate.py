"""Run labelled scenarios without mutating the application database."""
import json
import os
import time
from pathlib import Path
from types import SimpleNamespace
from netsentry.normalize import EventInput
from netsentry.detection import ATTACK,detect

ROOT=Path(__file__).resolve().parents[2]
SAMPLES=Path(os.getenv('NETSENTRY_SAMPLES_PATH',str(ROOT/'samples')))
def evaluate(path=None):
    path=path or SAMPLES/'evaluation_cases.json'
    cases=json.loads(Path(path).read_text())
    results=[]
    counts={r:{'tp':0,'fp':0,'fn':0,'tn':0} for r in ATTACK}
    for case in cases:
        events=[SimpleNamespace(id=i+1,**EventInput.model_validate(row).model_dump()) for i,row in enumerate(case['events'])]
        started=time.perf_counter()
        actual={x['rule'] for x in detect(events)}
        detection_ms=round((time.perf_counter()-started)*1000,3)
        expected=set(case['expected_rules'])
        results.append({'name':case['name'],'expected':sorted(expected),'detected':sorted(actual),'passed':actual==expected,'detection_ms':detection_ms})
        for rule in counts:
            key='tp' if rule in actual and rule in expected else 'fp' if rule in actual else 'fn' if rule in expected else 'tn'
            counts[rule][key]+=1
    def metrics(c):
        tp,fp,fn,tn=(c[x] for x in ('tp','fp','fn','tn'))
        precision=tp/(tp+fp) if tp+fp else 0
        recall=tp/(tp+fn) if tp+fn else 0
        return {**c,'precision':round(precision,3),'recall':round(recall,3),'f1':round(2*precision*recall/(precision+recall),3) if precision+recall else 0,'false_positive_rate':round(fp/(fp+tn),3) if fp+tn else 0}
    overall={k:sum(c[k] for c in counts.values()) for k in ('tp','fp','fn','tn')}
    return {'dataset':'labelled synthetic scenarios','scenario_count':len(cases),'passed_count':sum(r['passed'] for r in results),
        'failed_count':sum(not r['passed'] for r in results),'negative_scenario_count':sum(not c['expected_rules'] for c in cases),
        'confusion_matrix':overall,'detection_ms_total':round(sum(r['detection_ms'] for r in results),3),
        'overall':metrics(overall),'per_rule':{r:metrics(c) for r,c in counts.items()},'scenarios':results}

if __name__=='__main__':
    report=evaluate()
    out=ROOT/'docs/detection-evaluation.json'
    out.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report['overall'],indent=2))
    print('Wrote',out)
