'use strict';
const fs=require('node:fs');
function assessment(input){
  if(!input||input.authorization!=="owner_or_explicit_permission"||!Array.isArray(input.records))throw Error("Authorized local assessment record required");
  const validStates=["review_pending","confirmed","not_applicable","fix_pending","fixed_pending_retest","resolved"];
  const allowedPriority=["critical","high","medium","low","informational","unrated"];
  const counts=Object.fromEntries(validStates.map(x=>[x,0]));
  const priorities=Object.fromEntries(allowedPriority.map(x=>[x,0]));
  const seen=new Set();
  let confirmedOpen=0,verifiedResolved=0,unconfirmed=0,overdue=0;
  const reviewDate=input.as_of;
  const dateOK=d=>typeof d==="string"&&/^\d{4}-\d{2}-\d{2}$/.test(d)&&Number.isFinite(Date.parse(d))&&new Date(d).toISOString().slice(0,10)===d;
  if(!dateOK(reviewDate))throw Error("Valid as_of date required");
  const present=x=>typeof x==="string"&&x.trim().length>0;
  const verify=(x,label)=>{
    if(!x||!present(x.reviewer)||!present(x.evidence_ref)||!dateOK(x.date)||x.date>reviewDate||x.result!==label)throw Error("Incomplete or invalid "+label+" verification");
  };
  for(const r of input.records){
    if(!r||!present(r.id)||seen.has(r.id)||!validStates.includes(r.state)||!allowedPriority.includes(r.priority))throw Error("Invalid or duplicate record");
    seen.add(r.id);
    if(r.due!=null&&!dateOK(r.due))throw Error("Invalid due date");
    counts[r.state]++;
    if(["confirmed","fix_pending","fixed_pending_retest","resolved"].includes(r.state)){
      verify(r.initial_review,"confirmed");
      if(!present(r.owner)||!present(r.remediation))throw Error("Confirmed issue requires owner and remediation");
      if(r.state==="resolved"){
        verify(r.retest,"passed");
        if(r.retest.date<r.initial_review.date||r.retest.evidence_ref===r.initial_review.evidence_ref)throw Error("Resolution requires distinct retest evidence after initial review");
        verifiedResolved++;
      }else{
        confirmedOpen++;priorities[r.priority]++;
        if(r.due&&r.due<reviewDate)overdue++;
      }
    }else if(r.state==="not_applicable"){
      verify(r.initial_review,"not_applicable");
      if(!present(r.rationale))throw Error("Not applicable requires review rationale");
    }else unconfirmed++;
  }
  return {as_of:reviewDate,total:input.records.length,state_counts:counts,confirmed_open:confirmedOpen,unconfirmed,verified_resolved:verifiedResolved,overdue_confirmed_open:overdue,open_by_priority:priorities,notice:"Human-provided evidence attestations only. Does not authenticate evidence or verify exploitability. No identifiers, source snippets or evidence references in aggregate output."};
}
function selftest(){
  let passed=0;const check=(v,m)=>{if(!v)throw Error(m);passed++};const throws=(fn,m)=>{let fail=false;try{fn()}catch{fail=true}check(fail,m)};
  const wrap=(records)=>({authorization:"owner_or_explicit_permission",as_of:"2026-11-23",records});
  const p={id:"local-example",state:"review_pending",priority:"unrated"};
  const c={...p,state:"fix_pending",priority:"high",due:"2026-11-22",owner:"service owner",remediation:"apply reviewed patch",initial_review:{reviewer:"reviewer",evidence_ref:"private-before",date:"2026-11-20",result:"confirmed"}};
  const r={...c,state:"resolved",retest:{reviewer:"reviewer",evidence_ref:"private-after",date:"2026-11-22",result:"passed"}};
  check(assessment(wrap([p])).unconfirmed===1,"unverified separate");
  check(assessment(wrap([p])).confirmed_open===0,"unverified not confirmed");
  check(assessment(wrap([c])).confirmed_open===1,"confirmed");
  check(assessment(wrap([c])).overdue_confirmed_open===1,"overdue");
  check(assessment(wrap([c])).open_by_priority.high===1,"priority");
  check(assessment(wrap([r])).verified_resolved===1,"resolved");
  check(assessment(wrap([r])).confirmed_open===0,"resolved not open");
  check(!JSON.stringify(assessment(wrap([r]))).includes("private-before"),"evidence redacted");
  throws(()=>assessment(wrap([p,p])),"duplicate");
  throws(()=>assessment({...wrap([p]),authorization:"unknown"}),"authorization");
  throws(()=>assessment(wrap([{...c,initial_review:null}])),"missing initial review");
  throws(()=>assessment(wrap([{...r,retest:null}])),"missing retest");
  throws(()=>assessment(wrap([{...r,retest:{...r.retest,date:"2026-11-19"}}])),"old retest");
  throws(()=>assessment(wrap([{...r,retest:{...r.retest,date:"2026-11-24"}}])),"future retest");
  throws(()=>assessment(wrap([{...r,retest:{...r.retest,evidence_ref:"private-before"}}])),"same evidence");
  throws(()=>assessment(wrap([{...r,retest:{...r.retest,result:"failed"}}])),"failed retest");
  throws(()=>assessment(wrap([{...p,state:"not_applicable"}])),"unreviewed dismissal");
  throws(()=>assessment({...wrap([]),as_of:"2026-02-31"}),"bad date");
  check(assessment(wrap([])).total===0,"empty ledger");
  return {passed,failed:0};
}
if(require.main===module){
  try{
    const [cmd,file,flag]=process.argv.slice(2);
    if(cmd==="test")console.log(JSON.stringify(selftest(),null,2));
    else if(cmd==="review"&&file&&flag==="--authorized-local"){
      const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);
      try{const st=fs.fstatSync(fd);if(!st.isFile()||st.size>2*1024*1024)throw Error("Regular local file <=2 MiB required");console.log(JSON.stringify(assessment(JSON.parse(fs.readFileSync(fd,"utf8"))),null,2));}
      finally{fs.closeSync(fd);}
    }else throw Error("Usage: node remediation.js test | review FILE --authorized-local");
  }catch(e){console.error(e.message);process.exitCode=1;}
}
module.exports={assessment,selftest};
