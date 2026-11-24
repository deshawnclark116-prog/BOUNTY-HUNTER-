"""Compare explicit cookie attribute observations to independent rule fixtures.

Only source parsing; no application execution. Distinguishes unknown or
unrecognized calls from supported explicit controls. The expected labels
describe upstream rule behavior, not verified vulnerabilities.
"""
import json
import pathlib
import re
import runpy
import sys
import tokenize
from collections import defaultdict

ROOT = pathlib.Path(__file__).resolve().parents[1]
observe = runpy.run_path(str(ROOT/"python-defaults-review.py"))["cookie_control_observations"]
# Selected from rule names; fixture contents not inspected before evaluation.
# SameSite unsafe-value rule intentionally excluded: it demands literal Lax,
# whereas this reviewer recognizes Strict as restrictive as well.
FILES = {
    "python/pyramid/audit/set-cookie-httponly-unsafe-default.py": ("httponly","not_explicit"),
    "python/pyramid/audit/set-cookie-httponly-unsafe-value.py": ("httponly","disabled"),
    "python/pyramid/audit/set-cookie-samesite-unsafe-default.py": ("samesite","not_explicit"),
}

def evaluate(root):
    total = defaultdict(int)
    results = []
    for relative, (control, target) in FILES.items():
        path = root / relative
        with tokenize.open(path) as handle:
            source = handle.read()
        rows = observe(source)
        counts = dict(tp=0,tn=0,fp=0,fn=0,unknown_positive=0,unknown_negative=0,ambiguous=0)
        with path.open("rb") as f:
            for tok in tokenize.tokenize(f.readline):
                if tok.type != tokenize.COMMENT:
                    continue
                m = re.match(r"^#\s*(ruleid|ok)\s*:\s*(\S.*?)\s*$",tok.string,re.I)
                if not m:
                    continue
                line = tok.start[0]+1
                truth = m.group(1).lower()=="ruleid"
                matches = [r for r in rows if r["line"]<=line<=r["end_line"]]
                if len(matches)>1:
                    counts["ambiguous"] += 1
                elif not matches or matches[0][control]=="unknown":
                    counts["unknown_positive" if truth else "unknown_negative"]+=1
                else:
                    found=matches[0][control]==target
                    counts["tp" if truth and found else "fn" if truth else "fp" if found else "tn"]+=1
        for k,v in counts.items():
            total[k]+=v
        results.append({"file":relative,"recognized_calls":len(rows),**counts})
    return {"scope":"external rule fixture agreement; not vulnerability detection", "totals":dict(total),
            "labeled_cases":sum(total.values()),
            "precision":total["tp"]/(total["tp"]+total["fp"]) if total["tp"]+total["fp"] else None,
            "recall_including_unknown":total["tp"]/(total["tp"]+total["fn"]+total["unknown_positive"]) if total["tp"]+total["fn"]+total["unknown_positive"] else None,
            "files":results}

if __name__=="__main__":
    print(json.dumps(evaluate(pathlib.Path(sys.argv[1])),indent=2))
