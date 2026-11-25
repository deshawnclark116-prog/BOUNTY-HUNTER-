"""Deterministic local configuration expression tests; no inspected code execution.

Expected observations are computed from a separate table of explicit literal
settings. These are authored synthetic regressions, not an external holdout.
"""
import json
import pathlib
import runpy

ROOT=pathlib.Path(__file__).resolve().parents[1]
observe=runpy.run_path(str(ROOT/"python-defaults-review.py"))["cookie_control_observations"]
inspect=runpy.run_path(str(ROOT/"python-defaults-review.py"))["inspect_source"]

CONTROLS={
    "secure": [(True,"enabled"),(False,"disabled"),(None,"unknown"),("on","unknown")],
    "httponly": [(True,"enabled"),(False,"disabled"),(None,"unknown"),("on","unknown")],
    "samesite": [("Lax","restrictive"),("Strict","restrictive"),("None","cross_site"),(None,"disabled"),("invalid","unknown")],
}
def evaluate():
    count=0
    unknown=0
    wrong=0
    regression=0
    def check(control,body,expected):
        nonlocal count,unknown,wrong,regression
        source="from flask import Response\ndef build(condition):\n"
        source+="".join("    "+line+"\n" for line in body)
        source+="    r=Response()\n    r.set_cookie('demo','value',"+control+"=setting)\n"
        rows=observe(source)
        actual=rows[0][control] if len(rows)==1 else "missing"
        count+=1
        unknown+=actual=="unknown"
        wrong+=actual!=expected
        # The inventory is separate from literal-only legacy detection.
        if control=="secure":
            regression+=any(f["cwe"]==614 for f in inspect(source))
    for control, cases in CONTROLS.items():
        for value, state in cases:
            for body in [
                ["setting="+repr(value)],
                ["a="+repr(value),"setting=a"],
                ["setting=object()","setting="+repr(value)],
                ["if True:","    setting="+repr(value),"else:","    setting=object()"],
                ["if False:","    setting=object()","else:","    setting="+repr(value)],
                ["if condition:","    setting="+repr(value),"else:","    return"],
            ]:
                check(control,body,state)
        for left,left_state in cases:
            for right,right_state in cases:
                expected=left_state if type(left) is type(right) and left==right else "unknown"
                check(control,["if condition:","    setting="+repr(left),"else:","    setting="+repr(right)],expected)
        for body in [
            ["setting=True","setting=condition"],
            ["setting=True","setting=object()"],
            ["setting=True","for x in []:","    pass"],
            ["setting=True","del setting"],
            ["setting=True","if condition:","    setting=False"],
            ["setting=True","if condition:","    del setting"],
        ]:
            check(control,body,"unknown")
    return {"scope":"authored scalar configuration regression, not an external vulnerability test",
            "cases":count,"matching":count-wrong,"unknown_outputs":unknown,
            "mismatches":wrong,"legacy_secure_label_regressions":regression}

if __name__=="__main__":
    result=evaluate()
    print(json.dumps(result,indent=2))
    if result["mismatches"] or result["legacy_secure_label_regressions"]:
        raise SystemExit("Configuration values regression failed")
