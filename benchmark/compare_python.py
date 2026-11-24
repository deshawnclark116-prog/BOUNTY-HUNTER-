"""Compare existing static analyzer reports on the pinned public OWASP lab.

No code execution, network calls, target selection, or vulnerability confirmation.
"""
import json
import pathlib
import sys
from score_python import score
from score_semgrep import normalize

def index(report):
    scanned={pathlib.Path(p).stem for p in report["metrics"] if p!="_totals"}
    errors={pathlib.Path(e["filename"]).stem for e in report["errors"]}
    alerts=set()
    for r in report["results"]:
        cwe=r.get("issue_cwe",{}).get("id")
        if isinstance(cwe,int):
            alerts.add((pathlib.Path(r["filename"]).stem,cwe))
    return scanned,errors,alerts

def combined(left,right,mode):
    a,ae,aa=index(left)
    b,be,ba=index(right)
    if mode not in ("union","intersection"):
        raise ValueError("Unknown comparison mode")
    # Both analyzers must have evaluated a file for a fair comparison.
    common=(a&b)-(ae|be)
    alerts=(aa|ba) if mode=="union" else (aa&ba)
    return {"metrics":{p+".py":{} for p in sorted(common)},
            "errors":[{"filename":p+".py"} for p in sorted(ae|be)],
            "results":[{"filename":p+".py","issue_cwe":{"id":cwe}}
                       for p,cwe in sorted(alerts) if p in common]}

def test():
    a={"metrics":{"x.py":{},"y.py":{}},"errors":[],"results":[{"filename":"x.py","issue_cwe":{"id":1}}]}
    b={"metrics":{"x.py":{},"z.py":{}},"errors":[],"results":[{"filename":"x.py","issue_cwe":{"id":2}}]}
    assert len(combined(a,b,"union")["results"])==2
    assert len(combined(a,b,"intersection")["results"])==0
    assert set(combined(a,b,"union")["metrics"])=={"x.py"}
    b["errors"]=[{"filename":"x.py"}]
    assert not combined(a,b,"union")["metrics"]
    assert not combined(a,b,"union")["results"]
    print("5 comparison regression assertions passed")

if __name__=="__main__":
    if sys.argv[1:]==["test"]:
        test()
    else:
        key,bandit,semgrep,source=sys.argv[1:]
        with open(bandit,encoding="utf-8") as f:
            left=json.load(f)
        with open(semgrep,encoding="utf-8") as f:
            right,missing=normalize(json.load(f))
        scores={name:score(key,report,source) for name,report in (
            ("bandit",left),("semgrep",right),
            ("union",combined(left,right,"union")),
            ("intersection",combined(left,right,"intersection")))}
        print(json.dumps({"results":scores,"semgrep_missing_cwe":missing,
            "note":"Descriptive public-lab comparison only; not a new holdout or a production combined detector."},indent=2))
