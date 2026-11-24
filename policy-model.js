'use strict';
const fs=require('node:fs');
function auditPolicy(model){
  const fail=(m)=>{throw Error(m)};
  const isObj=x=>x!==null&&typeof x==="object"&&!Array.isArray(x);
  const name=x=>typeof x==="string"&&/^[A-Za-z][A-Za-z0-9_-]{0,47}$/.test(x);
  const names=(x,max,label)=>{
    if(!Array.isArray(x)||x.length<1||x.length>max||x.some(v=>!name(v))||new Set(x).size!==x.length)fail("Invalid "+label);
    return x;
  };
  if(!isObj(model)||model.environment!=="local_policy_design"||model.authorization!=="owner_or_explicit_permission"||model.schema_version!==1)fail("Explicit authorized local policy model required");
  const roles=names(model.roles,10,"roles"),actions=names(model.actions,16,"actions"),resources=names(model.resources,16,"resources");
  const relationships=["own","same_tenant","other_tenant"];
  const authStates=["authenticated","anonymous"];
  if(!Array.isArray(model.rules)||model.rules.length>200||!Array.isArray(model.contract)||model.contract.length>20000)fail("Invalid rule or contract collection");
  const unique=new Set();
  const selector=(v,domain)=>v==="*"||domain.includes(v);
  const rules=model.rules.map(r=>{
    if(!isObj(r)||!name(r.id)||unique.has(r.id)||!["allow","deny"].includes(r.effect)||!selector(r.role,roles)||!selector(r.action,actions)||!selector(r.resource,resources)||!selector(r.relationship,relationships)||!selector(r.auth,authStates))fail("Invalid or duplicate rule");
    unique.add(r.id);return r;
  });
  const key=(x)=>JSON.stringify([x.role,x.action,x.resource,x.relationship,x.auth]);
  const expected=new Map();
  for(const c of model.contract){
    if(!isObj(c)||!roles.includes(c.role)||!actions.includes(c.action)||!resources.includes(c.resource)||!relationships.includes(c.relationship)||!authStates.includes(c.auth)||!["allow","deny"].includes(c.expected)||expected.has(key(c)))fail("Invalid or duplicate contract row");
    expected.set(key(c),c.expected);
  }
  const totals={evaluated:0,contract_covered:0,contract_unknown:0,unintended_grants:0,missing_grants:0,conflicts:0,contract_matches:0};
  const findings=[],hits=new Map(rules.map(r=>[r.id,0]));
  for(const role of roles)for(const action of actions)for(const resource of resources)for(const relationship of relationships)for(const auth of authStates){
    const row={role,action,resource,relationship,auth};totals.evaluated++;
    const matching=rules.filter(r=>["role","action","resource","relationship","auth"].every(k=>r[k]==="*"||r[k]===row[k]));
    matching.forEach(r=>hits.set(r.id,hits.get(r.id)+1));
    const allow=matching.some(r=>r.effect==="allow"),deny=matching.some(r=>r.effect==="deny");
    const observed=allow&&!deny?"allow":"deny",want=expected.get(key(row));
    if(allow&&deny){totals.conflicts++;findings.push({...row,type:"overlapping_rules",status:"review_required"});}
    if(want===undefined){totals.contract_unknown++;continue;}
    totals.contract_covered++;
    if(want===observed)totals.contract_matches++;
    else if(want==="deny"){totals.unintended_grants++;findings.push({...row,type:"contract_overgrant",status:"model_mismatch"});}
    else{totals.missing_grants++;findings.push({...row,type:"contract_undergrant",status:"model_mismatch"});}
  }
  const complete=totals.contract_unknown===0;
  return {status:complete?"COMPLETE_MODEL_REVIEW":"PARTIAL_MODEL_REVIEW",totals,contract_coverage:totals.contract_covered/totals.evaluated,unmatched_rule_count:[...hits.values()].filter(v=>v===0).length,findings,notice:"Finite owner-provided authorization design only, deny-overrides/default-deny semantics. Not a test of deployed application behavior. Contract gaps remain unknown; model mismatches are not proof of exploitable vulnerabilities."};
}
function selftest(){
  const base={schema_version:1,environment:"local_policy_design",authorization:"owner_or_explicit_permission",roles:["reader","manager"],actions:["read","update"],resources:["record"],rules:[],contract:[]};
  for(const role of base.roles)for(const action of base.actions)for(const relationship of ["own","same_tenant","other_tenant"])for(const auth of ["authenticated","anonymous"]){
    base.contract.push({role,action,resource:"record",relationship,auth,expected:auth==="authenticated"&&relationship==="own"&&(action==="read"||role==="manager")?"allow":"deny"});
  }
  for(const c of base.contract.filter(c=>c.expected==="allow"))base.rules.push({id:"r"+base.rules.length,role:c.role,action:c.action,resource:c.resource,relationship:c.relationship,auth:c.auth,effect:"allow"});
  let passed=0;
  const check=(b,m)=>{if(!b)throw Error(m);passed++};
  const copy=()=>JSON.parse(JSON.stringify(base));
  const good=auditPolicy(base);
  check(good.totals.contract_matches===24,"reference matrix");
  check(good.totals.unintended_grants===0,"no overgrant");
  check(good.totals.missing_grants===0,"no undergrant");
  check(good.contract_coverage===1,"full contract");
  let m=copy();m.rules=[];check(auditPolicy(m).totals.missing_grants===3,"default deny");
  m=copy();m.rules[0].relationship="*";check(auditPolicy(m).totals.unintended_grants===2,"relationship expansion");
  m=copy();m.rules[0].auth="*";check(auditPolicy(m).totals.unintended_grants===1,"auth expansion");
  m=copy();m.rules.push({...m.rules[0],id:"deny",effect:"deny"});let v=auditPolicy(m);check(v.totals.conflicts===1&&v.totals.missing_grants===1,"deny overrides");
  m=copy();m.contract.pop();check(auditPolicy(m).status==="PARTIAL_MODEL_REVIEW","missing contract");
  for(const bad of [{...copy(),authorization:"unknown"},{...copy(),rules:[{...base.rules[0],role:"ghost"}]},{...copy(),contract:[base.contract[0],base.contract[0]]}]){
    let rejected=false;try{auditPolicy(bad)}catch{rejected=true}check(rejected,"invalid input rejected");
  }
  // Exhaustive deterministic single-cell regression: replace the rule table with
  // exact rules, invert each specified decision once, and check the independently specified contract.
  let mutations=0;
  for(const row of base.contract){
    m=copy();const i=m.rules.findIndex(r=>["role","action","resource","relationship","auth"].every(k=>r[k]===row[k]));
    if(i>=0)m.rules.splice(i,1);
    else m.rules.push({id:"extra",role:row.role,action:row.action,resource:row.resource,relationship:row.relationship,auth:row.auth,effect:"allow"});
    v=auditPolicy(m);
    check(v.totals.unintended_grants+v.totals.missing_grants===1,"exact single-cell mutation");
    mutations++;
  }
  return {passed,failed:0,synthetic_single_cell_mutations:mutations,scope:"authored local model regressions, not independent real-world detection"};
}
if(require.main===module){
 try{
  const [cmd,file,flag]=process.argv.slice(2);
  if(cmd==="test")console.log(JSON.stringify(selftest(),null,2));
  else if(cmd==="review"&&file&&flag==="--authorized-local"){
   const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);
   try{const st=fs.fstatSync(fd);if(!st.isFile()||st.size>2*1024*1024)throw Error("Regular local JSON file <=2 MiB required");const r=auditPolicy(JSON.parse(fs.readFileSync(fd,"utf8")));console.log(JSON.stringify(r,null,2));if(r.status==="PARTIAL_MODEL_REVIEW")process.exitCode=3;}
   finally{fs.closeSync(fd)}
  }else throw Error("Usage: node policy-model.js test | review FILE --authorized-local");
 }catch(e){console.error("Local model review failed");process.exitCode=1;}
}
module.exports={auditPolicy,selftest};
