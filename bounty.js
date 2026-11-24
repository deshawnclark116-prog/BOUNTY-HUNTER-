#!/usr/bin/env node
'use strict';
const fs = require('node:fs');
const directories = [
  {
    "name": "HackerOne",
    "url": "https://www.hackerone.com/bug-bounty-programs",
    "kind": "program directory"
  },
  {
    "name": "Bugcrowd",
    "url": "https://bugcrowd.com/programs",
    "kind": "program directory"
  },
  {
    "name": "Intigriti",
    "url": "https://www.intigriti.com/researchers/bug-bounty-programs",
    "kind": "program directory"
  },
  {
    "name": "OWASP Juice Shop",
    "url": "https://owasp.org/www-project-juice-shop/",
    "kind": "practice only"
  },
  {
    "name": "PortSwigger Web Security Academy",
    "url": "https://portswigger.net/web-security",
    "kind": "practice only"
  }
];
function reviewPolicy(p, today){
  const reasons=[];
  if(!p || typeof p!=="object") return {status:"BLOCKED",reasons:["No policy record"]};
  for(const k of ["program","policy_url","reviewed_by","scope_summary","restrictions","ai_rules","disclosure_rules"])
    if(typeof p[k]!=="string" || !p[k].trim()) reasons.push("Missing "+k);
  if(!/^https:\/\//.test(p.policy_url||"")) reasons.push("Official HTTPS policy link required");
  if(p.paid!==true) reasons.push("Payment eligibility not confirmed");
  if(p.participation_confirmed!==true) reasons.push("Participation eligibility not confirmed");
  if(p.manual_review_complete!==true) reasons.push("Policy has not been manually reviewed");
  if(p.local_review_allowed!==true) reasons.push("Offline review not confirmed allowed");
  if(p.ai_assistance_allowed!==true) reasons.push("AI assistance permission not confirmed");
  const d=Date.parse(p.reviewed_on), now=Date.parse(today);
  if(!Number.isFinite(d)||!Number.isFinite(now)||d>now||now-d>7*86400000) reasons.push("Policy review must be current (within 7 days)");
  return {status:reasons.length?"BLOCKED":"READY_FOR_MANUAL_REVIEW",reasons,notice:"Not authorization to test live systems. No live testing is implemented."};
}
function auditSample(sample){
  if(!sample||sample.environment!=="synthetic_local"||!Array.isArray(sample.cookies)) throw Error("Only synthetic local cookie configuration fixtures are supported");
  const findings=[];
  for(let i=0;i<sample.cookies.length;i++){
    const c=sample.cookies[i];
    if(!c||typeof c!=="object"||typeof c.session!=="boolean") throw Error("Invalid fixture cookie");
    if(!c.session) continue;
    for(const field of ["secure","httpOnly","sameSite"]){
      if(field==="sameSite" ? !["Strict","Lax","None"].includes(c[field]) : typeof c[field]!=="boolean") throw Error("Explicit fixture setting required: "+field);
    }
    if(!c.secure) findings.push({id:"COOKIE_SECURE",index:i,observation:"Synthetic session cookie lacks Secure",remediation:"Enable Secure on HTTPS session cookies."});
    if(!c.httpOnly) findings.push({id:"COOKIE_HTTPONLY",index:i,observation:"Synthetic session cookie lacks HttpOnly",remediation:"Enable HttpOnly when scripts do not require access."});
    if(c.sameSite==="None") findings.push({id:"COOKIE_SAMESITE_REVIEW",index:i,observation:"Synthetic session cookie uses SameSite=None",remediation:"Review cross-site requirements and CSRF protections; None can be legitimate."});
  }
  return {status:"PRACTICE_OBSERVATIONS_ONLY",findings,notice:"Configuration observations are not proof of exploitability or bounty eligibility."};
}
function selftest(){
  let count=0;const check=(v,msg)=>{if(!v)throw Error(msg);count++};
  const now="2026-11-23";
  const valid={program:"Example",policy_url:"https://example.invalid/policy",reviewed_by:"researcher",scope_summary:"Local fixture only",restrictions:"No network",ai_rules:"Local synthetic only",disclosure_rules:"Private",paid:true,participation_confirmed:true,manual_review_complete:true,local_review_allowed:true,ai_assistance_allowed:true,reviewed_on:now};
  check(reviewPolicy(valid,now).status==="READY_FOR_MANUAL_REVIEW","valid policy");
  for(const k of ["paid","participation_confirmed","manual_review_complete","local_review_allowed","ai_assistance_allowed"]) check(reviewPolicy({...valid,[k]:false},now).status==="BLOCKED",k);
  check(reviewPolicy({...valid,reviewed_on:"2026-11-01"},now).status==="BLOCKED","stale");
  check(reviewPolicy({...valid,reviewed_on:"2026-12-01"},now).status==="BLOCKED","future");
  check(reviewPolicy({...valid,scope_summary:""},now).status==="BLOCKED","scope");
  const base={environment:"synthetic_local",cookies:[{session:true,secure:true,httpOnly:true,sameSite:"Lax"}]};
  check(auditSample(base).findings.length===0,"clean control");
  check(auditSample({...base,cookies:[{session:true,secure:false,httpOnly:false,sameSite:"Lax"}]}).findings.length===2,"two planted issues");
  check(auditSample({...base,cookies:[{session:true,secure:true,httpOnly:true,sameSite:"None"}]}).findings[0].id==="COOKIE_SAMESITE_REVIEW","context review");
  let blocked=false;try{auditSample({...base,environment:"live"})}catch{blocked=true}check(blocked,"live blocked");
  blocked=false;try{auditSample({...base,cookies:[{session:true,secure:true}]})}catch{blocked=true}check(blocked,"incomplete input blocked");
  return {passed:count,failed:0};
}
function main(args){
  const [command,path]=args;
  const read=()=>JSON.parse(fs.readFileSync(path,'utf8'));
  if(command==='discover') return directories;
  if(command==='review') return reviewPolicy(read(),new Date().toISOString().slice(0,10));
  if(command==='practice') return auditSample(read());
  if(command==='test') return selftest();
  throw Error('Usage: node bounty.js discover | review FILE | practice FILE | test');
}
if(require.main===module){
  try{const result=main(process.argv.slice(2)); console.log(JSON.stringify(result,null,2)); if(result.status==='BLOCKED')process.exitCode=2;}
  catch(e){console.error(e.message);process.exitCode=1;}
}
module.exports={reviewPolicy,auditSample,selftest};
