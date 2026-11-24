"""Frozen reviewer vs independently authored Semgrep source fixtures.

Only parses local source. Labels are upstream ruleid/ok comments, not confirmed
vulnerabilities. Score exact next-line observation agreement by category.
Never execute the fixtures. Unlabeled observations remain unadjudicated.
"""
import json
import pathlib
import re
import runpy
import sys
import tokenize
from collections import defaultdict

ROOT = pathlib.Path(__file__).resolve().parents[1]
digest = runpy.run_path(str(ROOT/"digest-review.py"))["inspect_source"]
defaults = runpy.run_path(str(ROOT/"python-defaults-review.py"))["inspect_source"]
# File selection based on names, before reading fixture contents.
FILES = {
    "hash": [
        "python/cryptography/security/insecure-hash-algorithms-md5.py",
        "python/cryptography/security/insecure-hash-algorithms.py",
        "python/lang/security/insecure-hash-algorithms-md5.py",
        "python/lang/security/insecure-hash-algorithms.py",
        "python/lang/security/insecure-hash-function.py",
        "python/pycryptodome/security/insecure-hash-algorithm-md2.py",
        "python/pycryptodome/security/insecure-hash-algorithm-md4.py",
        "python/pycryptodome/security/insecure-hash-algorithm-md5.py",
        "python/pycryptodome/security/insecure-hash-algorithm.py",
    ],
    "tls": [
        "python/lang/security/audit/network/disabled-cert-validation.py",
        "python/lang/security/unverified-ssl-context.py",
        "python/requests/security/disabled-cert-validation.py",
    ],
    "cookie": [
        "python/flask/security/audit/secure-set-cookie.py",
        "python/pyramid/audit/set-cookie-secure-unsafe-default.py",
        "python/pyramid/audit/set-cookie-secure-unsafe-value.py",
    ],
}

def score(folder):
    all_rows=[]
    totals=defaultdict(lambda:dict(tp=0,tn=0,fp=0,fn=0,errors=0,unlabeled_flags=0,excluded_todo=0,ambiguous=0,files=0))
    for category, files in FILES.items():
        for rel in files:
            p=folder/rel
            g=totals[category]
            g["files"]+=1
            with tokenize.open(p) as f:
                source=f.read()
            expected=defaultdict(set)
            ignored=set()
            with p.open("rb") as f:
                for tok in tokenize.tokenize(f.readline):
                    if tok.type != tokenize.COMMENT:
                        continue
                    m=re.match(r"^#\s*(ruleid|ok|todoruleid|todook)\s*:\s*(\S.*?)\s*$",tok.string,re.I)
                    if not m:
                        continue
                    # Semgrep convention: directive directly before target line.
                    line=tok.start[0]+1
                    kind=m.group(1).lower()
                    if kind.startswith("todo"):
                        ignored.add(line)
                    else:
                        expected[line].add(kind=="ruleid")
            g["excluded_todo"]+=len(ignored)
            usable={line:next(iter(v)) for line,v in expected.items() if len(v)==1 and line not in ignored}
            g["ambiguous"]+=sum(len(v)>1 for v in expected.values())
            try:
                observations=(digest if category=="hash" else defaults)(source)
                cwe={"hash":328,"tls":295,"cookie":614}[category]
                flagged={x["line"] for x in observations if x["cwe"]==cwe}
            except (SyntaxError, ValueError, RecursionError, UnicodeError):
                g["errors"]+=len(usable)
                all_rows.append({"file":rel,"status":"analysis_error","labels":len(usable)})
                continue
            counts=dict(tp=0,tn=0,fp=0,fn=0)
            for line, truth in usable.items():
                prediction=line in flagged
                k="tp" if truth and prediction else "fn" if truth else "fp" if prediction else "tn"
                counts[k]+=1
                g[k]+=1
            extra=len(flagged-set(expected)-ignored)
            g["unlabeled_flags"]+=extra
            all_rows.append({"file":rel,**counts,"unlabeled_flags":extra})
    def metrics(g):
        p=g["tp"]+g["fp"]
        r=g["tp"]+g["fn"]
        return {**g,"precision":g["tp"]/p if p else None,"recall":g["tp"]/r if r else None,
                "labeled_evaluated":sum(g[k] for k in ("tp","tn","fp","fn"))}
    overall={k:sum(v[k] for v in totals.values()) for k in next(iter(totals.values()))}
    return {"scope":"unseen upstream rule fixture agreement; broader rule definitions and line conventions may differ",
            "overall":metrics(overall),"categories":{k:metrics(v) for k,v in totals.items()},"files":all_rows}

if __name__=="__main__":
    print(json.dumps(score(pathlib.Path(sys.argv[1])),indent=2))
