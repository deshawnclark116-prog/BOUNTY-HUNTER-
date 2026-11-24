"""Score an offline Bandit run against the public OWASP Python lab answer key."""
import csv
import json
import pathlib
import re
import sys
from collections import defaultdict

def score(key, report, source):
    labels = {}
    with open(key, encoding="utf-8-sig", newline="") as handle:
        for row in csv.reader(handle):
            if not row or row[0].startswith("#"):
                continue
            name, category, truth, cwe = (x.strip() for x in row[:4])
            if not re.fullmatch(r"BenchmarkTest[0-9]+", name) or name in labels or truth.lower() not in {"true","false"}:
                raise ValueError("Invalid or duplicate answer-key row")
            labels[name] = (category, truth.lower() == "true", int(cwe))
    source = pathlib.Path(source)
    actual = {p.stem for p in source.glob("BenchmarkTest*.py")}
    if actual != set(labels):
        raise ValueError(f"Dataset mismatch: {len(actual)} source cases vs {len(labels)} labels")
    metrics = report.get("metrics")
    if not isinstance(metrics, dict) or not isinstance(report.get("results"), list) or not isinstance(report.get("errors"), list):
        raise ValueError("Incomplete scanner report")
    scanned = {pathlib.Path(p).stem for p in metrics if p != "_totals"}
    errored = {pathlib.Path(x.get("filename","")).stem for x in report["errors"]}
    alerts = defaultdict(set)
    unmapped = 0
    for finding in report["results"]:
        name = pathlib.Path(finding["filename"]).stem
        cwe = finding.get("issue_cwe", {}).get("id")
        if name not in labels or not isinstance(cwe,int):
            unmapped += 1
            continue
        alerts[name].add(cwe)
    groups = defaultdict(lambda: dict(tp=0,tn=0,fp=0,fn=0,errors=0,positive_errors=0,negative_errors=0))
    for name, (category, truth, cwe) in labels.items():
        g = groups[category]
        if name in errored or name not in scanned:
            g["errors"] += 1
            g["positive_errors" if truth else "negative_errors"] += 1
            continue
        prediction = cwe in alerts[name]
        g["tp" if truth and prediction else "fn" if truth else "fp" if prediction else "tn"] += 1
    def summarize(g):
        tp,tn,fp,fn,errors=(g[k] for k in ("tp","tn","fp","fn","errors"))
        total=tp+tn+fp+fn+errors
        pos=tp+fn+g["positive_errors"]
        neg=tn+fp+g["negative_errors"]
        return dict(g, total=total, precision=tp/(tp+fp) if tp+fp else None,
                    recall=tp/pos if pos else None, specificity=tn/neg if neg else None,
                    coverage=(total-errors)/total if total else None)
    totals={k:sum(g[k] for g in groups.values()) for k in next(iter(groups.values()))}
    return {"dataset_cases":len(labels),"summary":summarize(totals),
            "categories":{k:summarize(v) for k,v in sorted(groups.items())},
            "unmapped_alerts":unmapped,
            "non_target_cwe_alerts":sum(len(cwes-{labels[name][2]}) for name,cwes in alerts.items()),
            "note":"Exact file and CWE agreement; other CWEs not adjudicated by answer key. No code executed. Not real-world discovery or bounty eligibility."}

if __name__=="__main__":
    with open(sys.argv[2],encoding="utf-8") as f:
        result=score(sys.argv[1],json.load(f),sys.argv[3])
    print(json.dumps(result,indent=2))
