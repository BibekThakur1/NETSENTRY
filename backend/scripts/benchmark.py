"""Synthetic API benchmark in isolated temporary databases. Not production capacity data."""
import argparse,json,os,platform,resource,subprocess,sys,tempfile,time
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]

def one_size(size):
    from fastapi.testclient import TestClient
    from netsentry.main import app
    start=time.perf_counter();results=[]
    with TestClient(app) as client:
        for chunk_index in range((size+9999)//10000):
            count=min(10000,size-chunk_index*10000)
            rows=[]
            for i in range(count):
                source=f'10.{chunk_index}.{(i//100)//256}.{(i//100)%256+1}'
                rows.append({'timestamp':f'2026-11-14T00:{(i//60)%60:02d}:{i%60:02d}Z','source_ip':source,
                             'event_type':'login_success','username':'normal-user'})
            payload=json.dumps(rows,separators=(',',':')).encode()
            t=time.perf_counter()
            response=client.post('/api/ingest',files={'file':(f'normal-{chunk_index}.json',payload,'application/json')})
            if response.status_code!=200:raise RuntimeError(f'Batch {chunk_index}: {response.status_code} {response.text[:300]}')
            results.append({'count':count,'wall_ms':round((time.perf_counter()-t)*1000,2),**response.json()})
        overview=client.get('/api/overview').json()
    elapsed=time.perf_counter()-start
    return {'events':size,'uploaded_files':len(results),'imported_events':overview['events'],'alerts':overview['alerts'],'incidents':overview['incidents'],
            'wall_seconds':round(elapsed,3),'throughput_events_per_second':round(size/elapsed,1),
            'detection_ms_total':round(sum(x['detection_ms'] for x in results),2),
            'correlation_ms_total':round(sum(x['correlation_ms'] for x in results),2),
            'ingest_request_ms_total':round(sum(x['wall_ms'] for x in results),2),
            'peak_rss_mb':round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss/1024/1024,1),
            'max_batch_events':max(x['count'] for x in results)}

def run():
    parser=argparse.ArgumentParser();parser.add_argument('--sizes',nargs='+',type=int,default=[1000,10000,100000]);parser.add_argument('--worker-size',type=int);args=parser.parse_args()
    if args.worker_size:
        print(json.dumps(one_size(args.worker_size)));return
    output=[]
    for size in args.sizes:
        with tempfile.TemporaryDirectory() as directory:
            env={**os.environ,'NETSENTRY_DATABASE_URL':'sqlite:///'+str(Path(directory)/'main.db'),
                 'NETSENTRY_DEMO_DATABASE_URL':'sqlite:///'+str(Path(directory)/'demo.db')}
            started=time.perf_counter()
            result=subprocess.run([sys.executable,'-m','scripts.benchmark','--worker-size',str(size)],cwd=str(ROOT/'backend'),env=env,capture_output=True,text=True,timeout=300)
            if result.returncode:raise RuntimeError(result.stderr or result.stdout)
            item=json.loads(result.stdout.strip().splitlines()[-1]);item['process_wall_seconds']=round(time.perf_counter()-started,3)
            output.append(item);print(f"{size}: {item['throughput_events_per_second']} events/s, {item['wall_seconds']} s, {item['peak_rss_mb']} MB",flush=True)
    report={'conditions':{'platform':platform.platform(),'python':platform.python_version(),'cpu_count':os.cpu_count(),
                          'database':'isolated SQLite file per size','transport':'FastAPI TestClient multipart requests',
                          'event_mix':'synthetic normal login_success, no expected alerts','file_limit':'10,000 events per upload',
                          'memory_note':'ru_maxrss peak for each isolated child process'},'results':output}
    path=ROOT/'docs/performance-benchmark.json';path.write_text(json.dumps(report,indent=2)+'\n');print('Wrote',path)
if __name__=='__main__':run()
