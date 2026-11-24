'use strict';
// Test adapter for pinned public Cedar fixtures, not a general Cedar implementation.
const fs=require('node:fs');
const path=require('node:path');
const {auditPolicy}=require('../policy-model.js');
const files=[...["1","2","3","4","5"].map(x=>"tests/multi/"+x+".json"),...["1a","2a","2b","2c","3a","3b","3c","4a","4d","4e","4f","5b"].map(x=>"tests/example_use_cases/"+x+".json")];
const supported=new Set(["tests/multi/1.json","tests/multi/2.json",...["1a","2a","2b","2c","3a","3b","3c"].map(x=>"tests/example_use_cases/"+x+".json")]);
const uid=x=>JSON.stringify([x.type,x.id]);
const entity='([A-Za-z][A-Za-z0-9_]*)::"([^"]+)"';
const root=process.argv[2];
if(!root)throw Error("Pinned public test directory required");
const read=p=>fs.readFileSync(path.join(root,p),"utf8");
const report={total_requests:0,evaluated:0,correct:0,incorrect:0,unsupported:0,allow:0,deny:0,unexpected_allow:0,unexpected_deny:0,suites:[]};
for(const file of files){
 const suite=JSON.parse(read(file)),n=suite.requests.length;
 report.total_requests+=n;
 if(!supported.has(file)){report.unsupported+=n;report.suites.push({file,total:n,status:"unsupported conditional or attribute semantics"});continue}
 const parents=new Map(JSON.parse(read(suite.entities)).map(e=>[uid(e.uid),e.parents.map(uid)]));
 function within(a,b){const seen=new Set(),todo=[a];while(todo.length){const q=todo.pop();if(q===b)return true;if(seen.has(q))continue;seen.add(q);todo.push(...(parents.get(q)||[]))}return false}
 const src=read(suite.policies).replace(/\/\/[^\n]*/g,"").trim();
 const policyRx=/(permit|forbid)\s*\(\s*([^,]+),\s*((?:[^\[\],]|\[[^\]]*\])+),\s*([^,)]+)\)\s*;/g;
 const parsed=[];let last=0;
 for(const m of src.matchAll(policyRx)){if(src.slice(last,m.index).trim())throw Error("Unsupported policy: "+file);last=m.index+m[0].length;parsed.push({effect:m[1]==="permit"?"allow":"deny",selectors:m.slice(2,5).map(s=>s.trim())})}
 if(!parsed.length||src.slice(last).trim())throw Error("Incomplete parse: "+file);
 const fields=["principal","action","resource"];
 const domains=fields.map(k=>[...new Set(suite.requests.map(r=>uid(r[k])))]);
 const ids=domains.map((d,i)=>new Map(d.map((x,j)=>[x,"e"+i+"_"+j])));
 function expand(selector,i){
  const field=fields[i];
  if(selector===field)return ["*"];
  const exact=selector.match(new RegExp("^"+field+"\\s+(==|in)\\s+"+entity+"$"));
  if(exact){const target=uid({type:exact[2],id:exact[3]});return domains[i].filter(x=>exact[1]==="=="?x===target:within(x,target)).map(x=>ids[i].get(x))}
  const list=selector.match(new RegExp("^"+field+"\\s+in\\s+\\[([^\\]]+)\\]$"));
  if(list){const values=list[1].split(",").map(t=>{const m=t.trim().match(new RegExp("^"+entity+"$"));if(!m)throw Error("Unsupported list");return uid({type:m[1],id:m[2]})});return domains[i].filter(x=>values.some(y=>within(x,y))).map(x=>ids[i].get(x))}
  throw Error("Unsupported selector: "+selector);
 }
 const rules=[];
 for(const p of parsed){const [a,b,c]=p.selectors.map(expand);for(const role of a)for(const action of b)for(const resource of c)rules.push({id:"rule"+rules.length,role,action,resource,relationship:"*",auth:"*",effect:p.effect})}
 const model={schema_version:1,environment:"local_policy_design",authorization:"owner_or_explicit_permission",roles:[...ids[0].values()],actions:[...ids[1].values()],resources:[...ids[2].values()],rules,contract:[]};
 let correct=0;
 for(const req of suite.requests){
  if(!["allow","deny"].includes(req.decision)||req.errors.length)throw Error("Unsupported label");
  model.contract=[{role:ids[0].get(uid(req.principal)),action:ids[1].get(uid(req.action)),resource:ids[2].get(uid(req.resource)),relationship:"other_tenant",auth:"authenticated",expected:req.decision}];
  const r=auditPolicy(model).totals;report.evaluated++;report[req.decision]++;
  if(r.contract_matches===1){correct++;report.correct++}else{report.incorrect++;if(req.decision==="deny")report.unexpected_allow++;else report.unexpected_deny++}
 }
 report.suites.push({file,total:n,correct,status:"evaluated"});
}
report.coverage=report.evaluated/report.total_requests;
report.accuracy=report.correct/report.evaluated;
console.log(JSON.stringify(report,null,2));
if(report.incorrect||!report.evaluated)process.exitCode=1;
