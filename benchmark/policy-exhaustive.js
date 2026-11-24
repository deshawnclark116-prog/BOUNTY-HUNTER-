'use strict';
const {auditPolicy}=require('../policy-model.js');
function stress(audit){
 const keys=["role","action","resource","relationship","auth"];
 const base={schema_version:1,environment:"local_policy_design",authorization:"owner_or_explicit_permission",roles:["R"],actions:["A"],resources:["P"],rules:[],contract:[]};
 const rows=["own","same_tenant","other_tenant"].flatMap(relationship=>["authenticated","anonymous"].map(auth=>({role:"R",action:"A",resource:"P",relationship,auth})));
 const wildcard={role:"*",action:"*",resource:"*",relationship:"*",auth:"*"};
 let checks=0,states=0,failed=0;const errors=[];
 const check=(ok,label)=>{checks++;if(!ok){failed++;if(errors.length<10)errors.push(label)}};
 const masks=[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63];
 // All 4^6 combinations of permit/deny membership. Use closed-form bitmask truth table,
 // three complete contracts, and one empty contract for each pair.
 for(const a of masks)for(const d of masks){
  const rules=[];
  for(let i=0;i<6;i++){
   if(a&(1<<i))rules.push({...rows[i],effect:"allow",id:"a"+i});
   if(d&(1<<i))rules.push({...rows[i],effect:"deny",id:"d"+i});
  }
  const actual=a&~d&63;
  const pop=n=>n.toString(2).replace(/0/g,"").length;
  for(const c of [0,63,21,null]){
   const contract=c===null?[]:rows.map((row,i)=>({...row,expected:c&(1<<i)?"allow":"deny"}));
   const result=audit({...base,rules,contract});const t=result.totals;
   states+=6;
   const expectedOver=c===null?0:pop(actual&~c&63),expectedUnder=c===null?0:pop(c&~actual&63);
   check(t.evaluated===6&&t.conflicts===pop(a&d)&&t.unintended_grants===expectedOver&&t.missing_grants===expectedUnder&&t.contract_unknown===(c===null?6:0)&&t.contract_matches===(c===null?0:6-expectedOver-expectedUnder)&&result.findings.length===pop(a&d)+expectedOver+expectedUnder&&result.status===(c===null?"PARTIAL_MODEL_REVIEW":"COMPLETE_MODEL_REVIEW"),"truth table "+a+"/"+d+"/"+c);
  }
 }
 const truthTable={models:checks,states,failures:failed};
 const max={...base,roles:Array.from({length:10},(_,i)=>"r"+i),actions:Array.from({length:16},(_,i)=>"a"+i),resources:Array.from({length:16},(_,i)=>"p"+i)};
 const bigRows=[];for(const role of max.roles)for(const action of max.actions)for(const resource of max.resources)for(const relationship of ["own","same_tenant","other_tenant"])for(const auth of ["authenticated","anonymous"])bigRows.push({role,action,resource,relationship,auth});
 const all=bigRows.length;
 max.rules=Array.from({length:200},(_,i)=>({...wildcard,id:"rule"+i,effect:i%2?"deny":"allow"}));
 max.contract=bigRows.map(row=>({...row,expected:"allow"}));
 const start=Date.now();const b=audit(max);const elapsed=Date.now()-start;
 check(b.totals.evaluated===all&&b.totals.conflicts===all&&b.totals.missing_grants===all&&b.findings.length===2*all,"maximum overlap/output");
 const rev=audit({...max,rules:[...max.rules].reverse(),contract:[...max.contract].reverse()});
 check(JSON.stringify(rev)===JSON.stringify(b),"maximum order invariance");
 check(JSON.stringify(max.contract[0])===JSON.stringify({...bigRows[0],expected:"allow"}),"input unchanged");
 const malformed=[
  {...base,roles:[null]}, {...base,roles:["*"]},{...base,roles:["R","R"]},{...base,resources:["x".repeat(49)]},
  {...base,rules:null},{...base,contract:null},{...base,rules:[null]},{...base,contract:[null]},
  {...base,rules:[{...wildcard,id:"duplicate",effect:"allow"},{...wildcard,id:"duplicate",effect:"deny"}]},
  {...base,rules:[{...wildcard,id:"bad",effect:"maybe"}]},
  {...base,rules:[{...wildcard,id:"bad",auth:"unknown",effect:"allow"}]},
  {...base,contract:[{...rows[0],expected:true}]},{...base,contract:[{...rows[0],expected:"deny"},{...rows[0],expected:"allow"}]},
  {...base,schema_version:2},{...base,authorization:null},{...base,environment:"production"},
  {...base,roles:["R\n"]},{...base,resources:["R/other"]},
  {...base,roles:[" R"]},{...base,rules:[{...wildcard,id:"bad",effect:"allow",resource:null}]}
 ];
 let rejected=0;for(const m of malformed){let ok=false;try{audit(m)}catch{ok=true;rejected++}check(ok,"malformed "+rejected)}
 return {truthTable,maximalModel:{states:all,rules:200,conflicts:b.totals.conflicts,findings:b.findings.length,elapsed_ms:elapsed},malformed:{total:malformed.length,rejected},total_assertions:checks,failed,errors,scope:"Exhaustive synthetic conformance over six-state truth table and bounded local design stress tests. No external targets or application execution."};
}
const result=stress(auditPolicy);
console.log(JSON.stringify(result,null,2));
if(result.failed)process.exitCode=1;
