"""Normalize Semgrep's public-lab report into the existing exact-CWE scoring format."""
import json
import pathlib
import re
import sys
from score_python import score

def normalize(data):
    if not isinstance(data.get("paths",{}).get("scanned"),list) or not isinstance(data.get("results"),list) or not isinstance(data.get("errors"),list):
        raise ValueError("Incomplete Semgrep output")
    scanned=data["paths"]["scanned"]
    errors=[]
    for error in data["errors"]:
        path=error.get("path")
        if not path:
            # Global or rule errors invalidate the comparison rather than silently treating them as negative cases.
            raise ValueError("Semgrep reported an unattributed analysis error: "+str(error.get("type","unknown")))
        errors.append({"filename":path})
    results=[]
    missing=0
    for finding in data["results"]:
        cwes=finding.get("extra",{}).get("metadata",{}).get("cwe",[])
        if not isinstance(cwes,list):
            cwes=[cwes]
        ids=set()
        for value in cwes:
            match=re.match(r"^CWE-([0-9]+)\b",str(value),re.I)
            if match:
                ids.add(int(match.group(1)))
        if not ids:
            missing+=1
        for cwe in sorted(ids):
            results.append({"filename":finding["path"],"issue_cwe":{"id":cwe}})
    return {"metrics":{p:{} for p in scanned},"errors":errors,"results":results},missing

if __name__=="__main__":
    with open(sys.argv[2],encoding="utf-8") as f:
        report,missing=normalize(json.load(f))
    result=score(sys.argv[1],report,sys.argv[3])
    result["alerts_without_cwe"]=missing
    print(json.dumps(result,indent=2))
