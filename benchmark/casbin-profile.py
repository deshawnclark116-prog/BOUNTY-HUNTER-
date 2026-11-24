"""Local test-only translation of the pinned public profile policy."""
import json
import sys
import casbin

model=casbin.Model()
model.load_model_from_text("""
[request_definition]
r = user, method, kind, owner, identified
[policy_definition]
p = method, kind, scope
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = r.method == p.method && r.kind == p.kind && (p.scope == "any" || (r.identified == "yes" && r.user == r.owner))
""")
e=casbin.Enforcer(model)
e.add_policy("POST","collection","any")
e.add_policy("GET","profile","self")
with open(sys.argv[1],encoding="utf-8") as f:
    rows=json.load(f)
results=[]
for row in rows:
    p=row["path"]
    kind="collection" if p==["users"] else "profile" if len(p)==2 and p[0]=="users" else "other"
    results.append(e.enforce(row.get("user_id",""),row["method"],kind,p[1] if len(p)>1 else "", "yes" if row.get("user_id") else "no"))
print(json.dumps(results))
