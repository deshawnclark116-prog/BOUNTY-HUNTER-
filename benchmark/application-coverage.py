"""Whole-application defensive coverage assessment of a public training lab.

This harness invokes existing local static reviewers only. It does not execute
application code, access endpoints, discover targets, or claim vulnerability
confirmation. Output is aggregated, with no source excerpts or finding paths.
"""
import ast
import json
import pathlib
import runpy
import sys
from collections import Counter

ROOT=pathlib.Path(__file__).resolve().parents[1]
digest=runpy.run_path(str(ROOT/"digest-review.py"))
defaults=runpy.run_path(str(ROOT/"python-defaults-review.py"))
MAX_FILES=2000

def evaluate(root):
    files=sorted(p for p in root.rglob("*.py") if ".git" not in p.relative_to(root).parts and not p.is_symlink())
    if len(files)>MAX_FILES:
        raise ValueError("Training source inventory exceeds bound")
    counters=Counter()
    statuses=Counter()
    observations=Counter()
    for p in files:
        try:
            source=digest["local_read"](p)
            ast.parse(source)
            a=digest["inspect_source"](source)
            b=defaults["inspect_source"](source)
            c=defaults["cookie_control_observations"](source)
            counters["fully_processed_python_files"]+=1
            counters["files_with_legacy_observations"]+=bool(a or b)
            counters["files_with_cookie_inventory"]+=bool(c)
            for row in a+b:
                observations[str(row["cwe"])]+=1
            for row in c:
                for control in ("secure","httponly","samesite"):
                    statuses[control+":"+row[control]]+=1
        except (OSError,ValueError,SyntaxError,RecursionError,UnicodeError):
            counters["analysis_errors"]+=1
    return {
        "scope":"public intentionally vulnerable training application; source-only configuration review",
        "python_files":len(files),
        "fully_processed_python_files":counters["fully_processed_python_files"],
        "analysis_errors":counters["analysis_errors"],
        "files_with_legacy_observations":counters["files_with_legacy_observations"],
        "files_with_cookie_inventory":counters["files_with_cookie_inventory"],
        "legacy_observations_by_cwe":dict(observations),
        "cookie_control_observations":dict(statuses),
        "application_runtime_assessed":False,
        "authorization_logic_extracted":False,
        "workflow_contract_extracted":False,
        "independent_issue_ground_truth_available":False,
        "confirmed_vulnerabilities":None,
        "precision":None,
        "recall":None,
        "gate":"NOT_MET",
        "reason":"source observations are not evidence of application-level discovery, impact, or reproducibility; no independent issue-level mapping"
    }

if __name__=="__main__":
    print(json.dumps(evaluate(pathlib.Path(sys.argv[1])),indent=2))
