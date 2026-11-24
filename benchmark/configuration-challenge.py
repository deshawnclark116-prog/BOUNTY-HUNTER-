"""Post-freeze defensive configuration review challenge.

Authored source fragments are parsed only, never executed. Expected labels
refer to explicit configuration observations under ordinary Python semantics.
No live application or actual vulnerability is tested.
"""
import json
import pathlib
import runpy

ROOT = pathlib.Path(__file__).resolve().parents[1]
digest = runpy.run_path(str(ROOT / "digest-review.py"))["inspect_source"]
defaults = runpy.run_path(str(ROOT / "python-defaults-review.py"))["inspect_source"]

CASES = [
    ("digest_basic", "digest", "import hashlib\nhashlib.md5(b'x')", True),
    ("digest_alias", "digest", "from hashlib import sha1 as h\nh(b'x')", True),
    ("digest_safe", "digest", "import hashlib\nhashlib.sha256(b'x')", False),
    ("digest_nonsecurity", "digest", "import hashlib\nhashlib.md5(b'x', usedforsecurity=False)", False),
    ("digest_dead_branch", "digest", "import hashlib\nif False:\n hashlib.md5(b'x')", False),
    ("digest_relative", "digest", "from .hashlib import md5\nmd5(b'x')", False),
    ("digest_relative_shadow", "digest", "import hashlib as h\nfrom .other import h\nh.md5(b'x')", False),
    ("digest_rebound", "digest", "import hashlib as h\nh=other\nh.md5(b'x')", False),
    ("digest_attribute_override", "digest", "import hashlib\nhashlib.md5 = custom\nhashlib.md5(b'x')", False),
    ("digest_after_return", "digest", "import hashlib\ndef f():\n return 0\n hashlib.md5(b'x')", False),
    ("tls_basic", "defaults", "import requests\nrequests.get(url, verify=False)", True),
    ("tls_safe", "defaults", "import requests\nrequests.get(url, verify=True)", False),
    ("tls_shadow", "defaults", "import requests as r\ndef f(r):\n r.get(url, verify=False)", False),
    ("tls_dead_branch", "defaults", "import requests\nif False:\n requests.get(url, verify=False)", False),
    ("tls_attribute_override", "defaults", "import requests\nrequests.get=custom\nrequests.get(url, verify=False)", False),
    ("tls_after_return", "defaults", "import requests\ndef f():\n return 0\n requests.get(url, verify=False)", False),
    ("cookie_basic", "defaults", "from flask import Response\nr=Response()\nr.set_cookie('id','x',secure=False)", True),
    ("cookie_secure", "defaults", "from flask import Response\nr=Response()\nr.set_cookie('id','x',secure=True)", False),
    ("cookie_attribute_override", "defaults", "from flask import Response\nr=Response()\nr.set_cookie=custom\nr.set_cookie('id','x')", False),
    ("cookie_dead_branch", "defaults", "from flask import Response\nif False:\n Response().set_cookie('id','x')", False),
    ("cookie_reassigned", "defaults", "from flask import Response\nr=Response()\nr=other\nr.set_cookie('id','x')", False),
    ("cookie_relative_import", "defaults", "from .flask import Response\nResponse().set_cookie('id','x')", False),
    ("cookie_shadow", "defaults", "from flask import Response\ndef f(Response):\n Response().set_cookie('id','x')", False),
    ("cookie_after_return", "defaults", "from flask import Response\ndef f():\n return 0\n Response().set_cookie('id','x')", False),
    ("cookie_dynamic", "defaults", "from flask import Response\nResponse().set_cookie('id','x',secure=setting)", None),
    ("digest_dynamic", "digest", "import hashlib\nhashlib.new(name)", None),
]

def evaluate():
    totals = dict(tp=0, tn=0, fp=0, fn=0, unresolved=0, unverified_flags=0)
    cases=[]
    for name, kind, source, expected in CASES:
        found=bool((digest if kind=="digest" else defaults)(source))
        bucket=("unverified_flags" if found else "unresolved") if expected is None else (
            "tp" if found and expected else "tn" if not found and not expected else "fp" if found else "fn")
        totals[bucket]+=1
        cases.append({"case":name,"category":bucket})
    return {"scope":"authored configuration observations, not real vulnerability detection", "totals":totals,"cases":cases}

if __name__=="__main__":
    result = evaluate()
    print(json.dumps(result,indent=2))
    counts = result["totals"]
    if counts != dict(tp=4, tn=20, fp=0, fn=0, unresolved=2, unverified_flags=0):
        raise SystemExit("Configuration observation regression failed")
