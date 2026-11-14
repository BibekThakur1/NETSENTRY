import csv, io, json
from fastapi import HTTPException
from pydantic import ValidationError
from .normalize import EventInput

MAX_BYTES=2_000_000
MAX_ROWS=10_000

def parse_upload(filename, data):
    if len(data)>MAX_BYTES: raise HTTPException(413,'File exceeds 2 MB limit')
    try: content=data.decode('utf-8-sig')
    except UnicodeDecodeError: raise HTTPException(400,'File must be UTF-8')
    ext=filename.lower().rsplit('.',1)[-1]
    try:
        if ext=='csv':
            rows=[{k:(None if v=='' and k not in ('bytes_transferred',) else 0 if v=='' and k=='bytes_transferred' else v) for k,v in row.items()} for row in csv.DictReader(io.StringIO(content))]
        elif ext=='json': rows=json.loads(content)
        else: raise HTTPException(400,'Only CSV and JSON files are supported')
    except (csv.Error,json.JSONDecodeError,RecursionError) as e: raise HTTPException(400,f'Invalid file: {e}')
    if not isinstance(rows,list) or not rows or len(rows)>MAX_ROWS: raise HTTPException(400,'File must contain 1 to 10,000 event rows')
    normalized=[]
    for index,row in enumerate(rows,1):
        if not isinstance(row,dict): raise HTTPException(422,{'row':index,'errors':[{'field':'row','code':'object_required'}]})
        try: normalized.append(EventInput.model_validate({**row, 'source_format':'generic', 'raw_event':row}))
        except ValidationError as exc:
            issues=[{'field':'.'.join(map(str,error['loc'])),'code':error['type']} for error in exc.errors(include_url=False,include_input=False)]
            raise HTTPException(422,{'row':index,'errors':issues})
    return normalized
