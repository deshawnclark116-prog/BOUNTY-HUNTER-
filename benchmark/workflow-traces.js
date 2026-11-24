'use strict';
const {reviewWorkflow}=require('../workflow-review.js');
function benchmark(review){
 const states=["pending","checked","closed"],roles=["staff","supervisor"],events=["check","close","reopen"];
 const transitions=[{from:"pending",event:"check",role:"staff",to:"checked"},{from:"checked",event:"close",role:"supervisor",to:"closed"},{from:"checked",event:"reopen",role:"supervisor",to:"pending"}];
 const base={schema_version:1,environment:"local_workflow_review",authorization:"owner_or_explicit_permission",states,roles,events,transitions};
 let seed=0x83ae51d9;
 const random=n=>{seed^=seed<<13;seed^=seed>>>17;seed^=seed<<5;return(seed>>>0)%n};
 const expected={consistent:0,inconsistent:0,unknown:0};
 const traces=[],labels=[];
 // Recorded synthetic examples only. The independent labeling function directly
 // specifies the expected workflow and event continuity, without using the rule map.
 for(let i=0;i<300;i++){
  const trace={id:"t"+i,initial_state:states[random(3)],events:[]};
  let last=trace.initial_state,seq=0;
  const label={consistent:0,inconsistent:0,unknown:0};
  for(let j=0;j<40;j++){
   const before=random(8)===0?null:random(5)===0?states[random(3)]:last;
   const after=random(8)===0?null:states[random(3)];
   const role=roles[random(2)],event=events[random(3)],outcome=["accepted","rejected",null][random(3)];
   const sequence=seq+(random(7)===0?2:1);
   const contiguous=sequence===seq+1;
   let mismatch=contiguous&&last!==null&&before!==null&&last!==before;
   if(before!==null&&outcome!==null){
    if(outcome==="rejected")mismatch ||= after!==null&&before!==after;
    else {
     const outcomes=before==="pending"&&role==="staff"&&event==="check"?["checked"]:
       before==="checked"&&role==="supervisor"&&event==="close"?["closed"]:
       before==="checked"&&role==="supervisor"&&event==="reopen"?["pending"]:[];
     mismatch ||= !outcomes.length||(after!==null&&!outcomes.includes(after));
    }
   }
   const status=mismatch?"inconsistent":!contiguous||last===null||before===null||after===null||outcome===null?"unknown":"consistent";
   expected[status]++;label[status]++;
   trace.events.push({sequence,event,role,observed_before:before,observed_after:after,outcome});
   last=after;seq=sequence;
  }
  traces.push(trace);labels.push(label);
 }
 const output=review({...base,traces});
 const disagreement=output.results.filter((r,i)=>Object.keys(labels[i]).some(k=>r[k]!==labels[i][k])).length;
 const max={...base,traces:Array.from({length:50},(_,i)=>({id:"m"+i,initial_state:"pending",events:Array.from({length:1000},(_,j)=>({sequence:j+1,event:"close",role:"staff",observed_before:"pending",observed_after:"pending",outcome:"rejected"}))}))};
 const start=Date.now();const maximum=review(max);const elapsed_ms=Date.now()-start;
 return {synthetic_traces:traces.length,synthetic_events:12000,expected,observed:{consistent:output.totals.consistent,inconsistent:output.totals.inconsistent,unknown:output.totals.unknown},trace_disagreements:disagreement,maximum_event_count:maximum.totals.events,maximum_consistent:maximum.totals.consistent,elapsed_ms};
}
const r=benchmark(reviewWorkflow);console.log(JSON.stringify(r,null,2));if(r.trace_disagreements||r.maximum_consistent!==50000)process.exitCode=1;
