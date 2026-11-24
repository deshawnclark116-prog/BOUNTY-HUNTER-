"""Compare existing local static-review reports on the pinned public lab."""
import json
import pathlib
import sys
from score_python import score
from score_semgrep import normalize
from compare_python import combined

def load(path):
    return json.loads(pathlib.Path(path).read_text(encoding="utf-8"))

if __name__ == "__main__":
    key, source, directory = sys.argv[1:]
    p = pathlib.Path(directory)
    own = combined(load(p/"digest.json"), load(p/"defaults.json"), "union")
    bandit = load(p/"bandit.json")
    semgrep, missing = normalize(load(p/"semgrep.json"))
    reports = {"bounty_hunter": own, "bandit": bandit, "semgrep": semgrep,
               "previous_scanner_union": combined(bandit, semgrep, "union")}
    results = {name:score(key, report, source) for name,report in reports.items()}
    output = {"results":results, "semgrep_alerts_without_cwe":missing,
              "note":"Same public development benchmark, exact case/CWE scoring; not a new blind holdout. Non-target alerts unadjudicated. No code executed or real vulnerabilities confirmed."}
    (p/"head-to-head.json").write_text(json.dumps(output,indent=2),encoding="utf-8")
    print(json.dumps({name:{"overall":r["summary"],"hash":r["categories"]["hash"],"securecookie":r["categories"]["securecookie"],"non_target_cwe_alerts":r["non_target_cwe_alerts"]} for name,r in results.items()},indent=2))
