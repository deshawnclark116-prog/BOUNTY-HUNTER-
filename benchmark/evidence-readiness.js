'use strict';
const {reviewWorkflow}=require('../workflow-review.js');
const {reviewReport}=require('../research.js');
function acceptanceChallenge(review,report){
 // Entirely fabricated local observations. No real assets, targets, secrets or reports.
 const base={schema_version:1,environment:"local_workflow_review",authorization:"owner_or_explicit_permission",states:["draft","reviewed","archived"],roles:["author","reviewer"],events:["submit","archive"],transitions:[{from:"draft",role:"author",event:"submit",to:"reviewed"},{from:"reviewed",role:"reviewer",event:"archive",to:"archived"}]};
 const e=(sequence,event,role,observed_before,observed_after,outcome)=>({sequence,event,role,observed_before,observed_after,outcome});
 const scenarios=[
  {name:"valid_record",truth:"negative",events:[e(1,"submit","author","draft","reviewed","accepted"),e(2,"archive","reviewer","reviewed","archived","accepted")]},
  {name:"rejected_unchanged",truth:"negative",events:[e(1,"archive","author","draft","draft","rejected")]},
  {name:"recorded_contract_discrepancy",truth:"positive",events:[e(1,"archive","author","draft","archived","accepted")]},
  {name:"incorrect_result_state",truth:"positive",events:[e(1,"submit","author","draft","archived","accepted")]},
  {name:"rejection_changed_state",truth:"positive",events:[e(1,"submit","author","draft","reviewed","rejected")]},
  {name:"accepted_undeclared_missing_result",truth:"positive",events:[e(1,"archive","author","draft",null,"accepted")]},
  {name:"incomplete_outcome",truth:"unknown",events:[e(1,"submit","author","draft","reviewed",null)]},
  {name:"incomplete_state",truth:"unknown",events:[e(1,"submit","author","draft",null,"accepted")]},
  {name:"missing_event_record",truth:"unknown",events:[e(2,"submit","author","draft","reviewed","accepted")]},
  {name:"unproven_empty_record",truth:"unknown",events:[]}
 ];
 const findings={tp:0,tn:0,fp:0,fn:0,unknown_positive:0,unknown_negative:0,unknown_expected:0,unwarranted_definite:0};
 const rows=[];
 for(const s of scenarios){
  const r=review({...base,traces:[{id:"fixture",initial_state:"draft",events:s.events}]});
  const got=r.totals.inconsistent?"positive":r.totals.unknown||r.totals.empty_traces?"unknown":"negative";
  const key=s.truth==="positive"?(got==="positive"?"tp":got==="unknown"?"unknown_positive":"fn"):s.truth==="negative"?(got==="negative"?"tn":got==="unknown"?"unknown_negative":"fp"):got==="unknown"?"unknown_expected":"unwarranted_definite";
  findings[key]++;
  rows.push({scenario:s.name,expected:s.truth,observed:got,category:key});
 }
 // Actual report gate tested as a checklist, not an authenticated decision-maker.
 const fields=["official_policy_reference","authorized_scope_reference","evidence_reference","expected_behavior","observed_behavior","demonstrated_impact","remediation","reviewer"];
 const flags=["current_policy_checked","participation_confirmed","scope_confirmed","method_permitted","ai_policy_compliant","evidence_independently_verified","privacy_redacted","duplicate_check_complete","human_approved"];
 const fixture={environment:"synthetic_local",practice_only:true};
 for(const k of fields)fixture[k]="synthetic fixture only";
 for(const k of flags)fixture[k]=false;
 const honest=scenarios.map(()=>report(fixture).status);
 const checked={...fixture,environment:"authorized_research",practice_only:false};
 for(const k of flags)checked[k]=true;
 const missingChecks=[...fields,...flags].map(k=>{const v={...checked};delete v[k];return report(v).status});
 // Contrived self-attestations intentionally do not constitute actual evidence.
 const assertionOnly=report(checked);
 return {scope:"authored local evidence-readiness challenge; no actual reports or payouts",workflow:{cases:rows.length,findings,precision:findings.tp/(findings.tp+findings.fp),recall_including_abstention:findings.tp/(findings.tp+findings.fn+findings.unknown_positive),rows},report_gate:{honestly_labeled_practice_cases:honest.length,practice_cases_blocked:honest.filter(x=>x==="BLOCKED").length,missing_required_field_cases:missingChecks.length,missing_required_field_blocked:missingChecks.filter(x=>x==="BLOCKED").length,assertion_only_status:assertionOnly.status,authenticated_evidence:false},actual_verified_vulnerabilities:0,actual_submissions:0,actual_payouts:0};
}
const r=acceptanceChallenge(reviewWorkflow,reviewReport);console.log(JSON.stringify(r,null,2));if(r.workflow.findings.tp!==4||r.workflow.findings.fp||r.workflow.findings.unknown_expected!==4||r.report_gate.assertion_only_status!=="CHECKLIST_COMPLETE_UNVERIFIED"||r.report_gate.practice_cases_blocked!==r.report_gate.honestly_labeled_practice_cases||r.report_gate.missing_required_field_blocked!==r.report_gate.missing_required_field_cases)process.exitCode=1;
