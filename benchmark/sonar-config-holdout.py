"""Frozen local reviewer against separate SonarSource annotated fixtures.

Static parsing only. Explicit Noncompliant/Compliant comments only; unlabeled
lines are never negative controls. Upstream hotspots are review expectations,
not verified security impact. No source snippets are emitted.
"""
import pathlib
import re
import runpy
import tokenize
import json
import sys
from collections import defaultdict

ROOT=pathlib.Path(__file__).resolve().parents[1]
digest=runpy.run_path(str(ROOT/"digest-review.py"))["inspect_source"]
default_module=runpy.run_path(str(ROOT/"python-defaults-review.py"))
defaults=default_module["inspect_source"]
cookie=default_module["cookie_control_observations"]
FILES={
    "verifiedSslTlsCertificateCheck.py":"tls",
    "hotspots/hashing/hashingData.py":"hash",
    "hotspots/secureCookie.py":"secure",
    "hotspots/httpOnlyCookie.py":"httponly",
}

def score(root):
    results=[]
    totals=defaultdict(int)
    for rel,kind in FILES.items():
        p=root/"python-checks/src/test/resources/checks"/rel
        counts=dict(tp=0,tn=0,fp=0,fn=0,unknown_positive=0,unknown_negative=0,
                    conflicting_labels=0,unparsed_markers=0,unadjudicated_flags=0,analysis_errors=0)
        labels=defaultdict(set)
        with tokenize.open(p) as f:
            source=f.read()
        with p.open("rb") as f:
            for token in tokenize.tokenize(f.readline):
                if token.type!=tokenize.COMMENT:
                    continue
                marker=re.search(r"\b(Noncompliant|Compliant)\b",token.string)
                if not marker:
                    continue
                tail=token.string[marker.end():]
                offset=re.match(r"\s*@([+-]?\d+)\b",tail)
                if tail.lstrip().startswith("@") and not offset:
                    counts["unparsed_markers"]+=1
                    continue
                line=token.start[0]+int(offset.group(1)) if offset else token.start[0]
                labels[line].add(marker.group(1)=="Noncompliant")
        try:
            if kind in {"secure","httponly"}:
                rows=cookie(source)
                flags={r["line"] for r in rows if r[kind] in {"disabled","not_explicit"}}
                def outcome(line):
                    found=[r[kind] for r in rows if r["line"]<=line<=r["end_line"]]
                    if len(found)!=1 or found[0]=="unknown":
                        return None
                    return found[0] in {"disabled","not_explicit"}
            else:
                rows=(digest if kind=="hash" else defaults)(source)
                cwe=328 if kind=="hash" else 295
                flags={r["line"] for r in rows if r["cwe"]==cwe}
                def outcome(line):
                    return line in flags
            for line,truths in labels.items():
                if len(truths)!=1:
                    counts["conflicting_labels"]+=1
                    continue
                truth=next(iter(truths))
                found=outcome(line)
                k=("unknown_positive" if truth else "unknown_negative") if found is None else (
                    "tp" if truth and found else "fn" if truth else "fp" if found else "tn")
                counts[k]+=1
            counts["unadjudicated_flags"]=len(flags-set(labels))
        except (SyntaxError, ValueError, RecursionError, UnicodeError):
            counts["analysis_errors"]+=1
            for truths in labels.values():
                if len(truths)==1:
                    counts["unknown_positive" if next(iter(truths)) else "unknown_negative"]+=1
                else:
                    counts["conflicting_labels"]+=1
        results.append({"file":rel,"category":kind,**counts})
        for k,v in counts.items():
            totals[k]+=v
    n=sum(totals[k] for k in ("tp","tn","fp","fn","unknown_positive","unknown_negative"))
    positives=totals["tp"]+totals["fn"]+totals["unknown_positive"]
    findings=totals["tp"]+totals["fp"]
    precision=totals["tp"]/findings if findings else None
    recall=totals["tp"]/positives if positives else None
    coverage=sum(totals[k] for k in ("tp","tn","fp","fn"))/n if n else None
    passed=n>=100 and precision is not None and precision>=.95 and recall is not None and recall>=.8 and coverage==1 and not any(totals[k] for k in ("analysis_errors","conflicting_labels","unparsed_markers"))
    return {"scope":"public SonarSource explicit annotation agreement; not vulnerability truth or secret blind holdout",
            "total":dict(totals),"labeled_cases":n,"precision":precision,"recall_including_unknown":recall,"definitive_coverage":coverage,
            "gate":"MET_FOR_FIXTURE_AGREEMENT_ONLY" if passed else "NOT_MET","files":results}
if __name__=="__main__":
    print(json.dumps(score(pathlib.Path(sys.argv[1])),indent=2))
