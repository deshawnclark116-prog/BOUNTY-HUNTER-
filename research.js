#!/usr/bin/env node
'use strict';
const fs=require('node:fs');
function evaluateCase(c){
  if(!c||c.environment!=="synthetic_local"||!Array.isArray(c.checks)||!c.checks.length) throw Error("Nonempty synthetic local fixture required");
  const known=["authorization","data_isolation","session_lifecycle","input_validation","error_handling","data_integrity","privacy","configuration"];
  const ids=new Set(), findings=[],unknown=[];
  for(const check of c.checks){
    if(!check||typeof check.id!=="string"||!check.id.trim()||ids.has(check.id)||!known.includes(check.category)) throw Error("Invalid or duplicate check");
    ids.add(check.id);
    if(typeof check.expected!=="boolean"||!(typeof check.observed==="boolean"||check.observed===null)) throw Error("Expected boolean and observed boolean/null required");
    if(check.observed===null) unknown.push(check.id);
    else if(check.expected!==check.observed) findings.push({id:check.id,category:check.category,expected:check.expected,observed:check.observed,status:"LOCAL_CONTROL_MISMATCH"});
  }
  return {findings,unknown,checked:ids.size,status:"LOCAL_BENCHMARK_ONLY"};
}
function benchmark(){
  const categories=["authorization","data_isolation","session_lifecycle","input_validation","error_handling","data_integrity","privacy","configuration"];
  let tp=0,tn=0,fp=0,fn=0,abstain=0;
  const results=[];
  for(const category of categories){
    const counts={tp:0,tn:0,fp:0,fn:0,abstain:0};
    // Truth table controls, not a real-world or independent holdout dataset.
    for(const expected of [true,false]){
      for(const observed of [true,false,null]){
        const id=category+":"+expected+":"+observed;
        const r=evaluateCase({environment:"synthetic_local",checks:[{id,category,expected,observed}]});
        const prediction=r.findings.length>0;
        const truth=observed!==null&&observed!==expected;
        const key=observed===null?(r.unknown.includes(id)?"abstain":"fn"):truth?(prediction?"tp":"fn"):(prediction?"fp":"tn");
        counts[key]++;
      }
    }
    tp+=counts.tp;tn+=counts.tn;fp+=counts.fp;fn+=counts.fn;abstain+=counts.abstain;
    results.push({category,...counts});
  }
  return {dataset:"synthetic truth-table regression, not independent vulnerability detection",tp,tn,fp,fn,abstain,precision:tp/(tp+fp),recall:tp/(tp+fn),specificity:tn/(tn+fp),results};
}
function summarizeLedger(rows){
  if(!Array.isArray(rows))throw Error("Ledger must be an array");
  const ids=new Set(); const counts={research:0,submitted:0,accepted:0,paid:0,duplicate:0,rejected:0,closed_no_report:0};
  let hours=0,cost=0,payout=0;
  for(const r of rows){
    if(!r||typeof r.id!=="string"||!r.id.trim()||ids.has(r.id)||!Object.hasOwn(counts,r.status))throw Error("Invalid or duplicate ledger item");
    ids.add(r.id);
    for(const k of ["hours","cost_cents","payout_cents"])if(typeof r[k]!=="number"||!Number.isFinite(r[k])||r[k]<0||(k!=="hours"&&!Number.isSafeInteger(r[k])))throw Error("Invalid "+k);
    if(r.status==="paid"?r.payout_cents<=0:r.payout_cents!==0)throw Error("Only confirmed paid outcomes count as income");
    counts[r.status]++;hours+=r.hours;cost+=r.cost_cents;payout+=r.payout_cents;
  }
  const resolved=counts.accepted+counts.paid+counts.duplicate+counts.rejected;
  return {records:rows.length,counts,hours,cost_cents:cost,actual_payout_cents:payout,net_cents:payout-cost,net_per_hour_usd:hours?((payout-cost)/100)/hours:null,acceptance_rate_resolved:resolved?(counts.accepted+counts.paid)/resolved:null,duplicate_rate_resolved:resolved?counts.duplicate/resolved:null,notice:"Historical accounting only; no estimated or promised income."};
}
function reviewReport(r){
  const fields=["official_policy_reference","authorized_scope_reference","evidence_reference","expected_behavior","observed_behavior","demonstrated_impact","remediation","reviewer"];
  const flags=["current_policy_checked","participation_confirmed","scope_confirmed","method_permitted","ai_policy_compliant","evidence_independently_verified","privacy_redacted","duplicate_check_complete","human_approved"];
  const missing=[];
  for(const k of fields)if(typeof r?.[k]!=="string"||!r[k].trim())missing.push(k);
  for(const k of flags)if(r?.[k]!==true)missing.push(k);
  if(r?.environment!=="authorized_research")missing.push("authorized_research environment");
  if(r?.practice_only!==false)missing.push("practice_only must be false");
  return {status:missing.length?"BLOCKED":"READY_FOR_HUMAN_SUBMISSION_DECISION",missing,notice:"Checklist only; assertions are not independently authenticated. No submission or live testing."};
}
function selftest(){
  let n=0;const check=(x,m)=>{if(!x)throw Error(m);n++};const throws=(f,m)=>{let ok=false;try{f()}catch{ok=true}check(ok,m)};
  const b=benchmark();check(b.tp===16,"TP");check(b.tn===16,"TN");check(b.fp===0&&b.fn===0,"FP/FN");check(b.abstain===16,"unknown");
  const c={environment:"synthetic_local",checks:[{id:"x",category:"privacy",expected:true,observed:false}]};
  check(evaluateCase(c).findings.length===1,"mismatch");throws(()=>evaluateCase({...c,environment:"live"}),"reject live");throws(()=>evaluateCase({...c,checks:[...c.checks,...c.checks]}),"duplicate");throws(()=>evaluateCase({...c,checks:[]}),"empty");throws(()=>evaluateCase({...c,checks:[{...c.checks[0],observed:"false"}]}),"bad type");
  const a={id:"a",status:"paid",hours:2,cost_cents:100,payout_cents:10000};
  check(summarizeLedger([a]).net_per_hour_usd===49.5,"net hourly");check(summarizeLedger([]).acceptance_rate_resolved===null,"empty not zero");throws(()=>summarizeLedger([a,a]),"duplicate ledger");throws(()=>summarizeLedger([{...a,status:"submitted"}]),"no premature revenue");throws(()=>summarizeLedger([{...a,hours:-1}]),"negative");
  const r={environment:"authorized_research",practice_only:false};
  for(const k of ["official_policy_reference","authorized_scope_reference","evidence_reference","expected_behavior","observed_behavior","demonstrated_impact","remediation","reviewer"])r[k]="synthetic placeholder for test only";
  const flags=["current_policy_checked","participation_confirmed","scope_confirmed","method_permitted","ai_policy_compliant","evidence_independently_verified","privacy_redacted","duplicate_check_complete","human_approved"];
  for(const k of flags)r[k]=true;
  check(reviewReport(r).status==="READY_FOR_HUMAN_SUBMISSION_DECISION","complete checklist");
  for(const k of flags)check(reviewReport({...r,[k]:false}).status==="BLOCKED",k);
  check(reviewReport({...r,practice_only:true}).status==="BLOCKED","practice blocked");
  check(reviewReport(null).status==="BLOCKED","empty report");
  return {passed:n,failed:0,benchmark:b};
}
if(require.main===module){
 try{
  const [command,path]=process.argv.slice(2);
  const read=()=>JSON.parse(fs.readFileSync(path,'utf8'));
  const commands={test:()=>selftest(),benchmark:()=>benchmark(),practice:()=>evaluateCase(read()),ledger:()=>summarizeLedger(read()),report:()=>reviewReport(read())};
  if(!Object.hasOwn(commands,command))throw Error('Usage: node research.js test | benchmark | practice FILE | ledger FILE | report FILE');
  const result=commands[command]();console.log(JSON.stringify(result,null,2));if(result.status==='BLOCKED')process.exitCode=2;
 }catch(e){console.error(e.message);process.exitCode=1;}
}
module.exports={evaluateCase,benchmark,summarizeLedger,reviewReport,selftest};
