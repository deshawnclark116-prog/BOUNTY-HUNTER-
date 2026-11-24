'use strict';
const fs=require('node:fs');
function reviewWorkflow(model){
 const bad=()=>{throw Error("Invalid local workflow review model")};
 const obj=x=>x!==null&&typeof x==="object"&&!Array.isArray(x);
 const name=x=>typeof x==="string"&&/^[A-Za-z][A-Za-z0-9_-]{0,47}$/.test(x);
 const own=(o,k)=>Object.prototype.hasOwnProperty.call(o,k);
 const fields=(o,keys)=>{if(!obj(o)||Object.keys(o).length!==keys.length||keys.some(k=>!own(o,k)))bad()};
 const names=(a,max)=>{if(!Array.isArray(a)||!a.length||a.length>max||a.some(x=>!name(x))||new Set(a).size!==a.length)bad();return new Set(a)};
 fields(model,["schema_version","environment","authorization","states","roles","events","transitions","traces"]);
 if(model.schema_version!==1||model.environment!=="local_workflow_review"||model.authorization!=="owner_or_explicit_permission")bad();
 const states=names(model.states,32),roles=names(model.roles,32),events=names(model.events,64);
 if(!Array.isArray(model.transitions)||model.transitions.length>512||!Array.isArray(model.traces)||!model.traces.length||model.traces.length>1000)bad();
 const key=(s,e,r)=>JSON.stringify([s,e,r]);
 const rules=new Map();
 for(const t of model.transitions){
  fields(t,["from","event","role","to"]);
  if(!states.has(t.from)||!states.has(t.to)||!events.has(t.event)||!roles.has(t.role)||rules.has(key(t.from,t.event,t.role)))bad();
  rules.set(key(t.from,t.event,t.role),t.to);
 }
 const ids=new Set();let eventCount=0;
 for(const t of model.traces){
  fields(t,["id","initial_state","events"]);
  if(!name(t.id)||ids.has(t.id)||!states.has(t.initial_state)||!Array.isArray(t.events)||t.events.length>1000)bad();
  ids.add(t.id);eventCount+=t.events.length;if(eventCount>50000)bad();
  for(const e of t.events){
   fields(e,["sequence","event","role","observed_before","observed_after","outcome"]);
   if(!Number.isSafeInteger(e.sequence)||e.sequence<1||!events.has(e.event)||!roles.has(e.role)||![null,...states].includes(e.observed_before)||![null,...states].includes(e.observed_after)||!["accepted","rejected",null].includes(e.outcome))bad();
  }
 }
 const totals={traces:model.traces.length,events:eventCount,consistent:0,inconsistent:0,unknown:0,empty_traces:0};
 const results=[];
 for(const t of model.traces){
  let prior=t.initial_state,sequence=0;const counts={consistent:0,inconsistent:0,unknown:0},reasons={};
  for(const e of t.events){
   const flags=[];
   if(e.sequence<=sequence)flags.push("nonmonotonic_sequence");
   const contiguous=e.sequence===sequence+1;
   if(contiguous&&prior!==null&&e.observed_before!==null&&prior!==e.observed_before)flags.push("state_discontinuity");
   if(e.observed_before!==null&&e.outcome!==null){
    const allowed=rules.get(key(e.observed_before,e.event,e.role));
    if(e.outcome==="accepted"){
     if(allowed===undefined)flags.push("undeclared_accepted_transition");
     else if(e.observed_after!==null&&e.observed_after!==allowed)flags.push("unexpected_result_state");
    }else if(e.observed_after!==null&&e.observed_before!==e.observed_after)flags.push("rejected_event_changed_state");
   }
   const status=flags.length?"inconsistent":!contiguous||prior===null||e.observed_before===null||e.observed_after===null||e.outcome===null?"unknown":"consistent";
   counts[status]++;totals[status]++;
   for(const flag of flags)reasons[flag]=(reasons[flag]||0)+1;
   prior=e.observed_after;sequence=Math.max(sequence,e.sequence);
  }
  if(!t.events.length)totals.empty_traces++;
  results.push({trace_id:t.id,...counts,reasons});
 }
 return {status:totals.inconsistent?"MODEL_MISMATCH":totals.unknown||totals.empty_traces?"PARTIAL_REVIEW":"OBSERVED_TRACES_CONSISTENT",totals,results,notice:"Checks owner-supplied recorded workflow events against an explicit design contract. No event generation, application interaction or claim of complete workflow coverage. Results are design/trace discrepancies, not confirmed vulnerabilities."};
}
function selftest(){
 const base={schema_version:1,environment:"local_workflow_review",authorization:"owner_or_explicit_permission",states:["draft","reviewed","archived"],roles:["author","reviewer"],events:["submit","archive"],transitions:[{from:"draft",role:"author",event:"submit",to:"reviewed"},{from:"reviewed",role:"reviewer",event:"archive",to:"archived"}],traces:[]};
 const ev=(sequence,event,role,observed_before,observed_after,outcome="accepted")=>({sequence,event,role,observed_before,observed_after,outcome});
 const good=[ev(1,"submit","author","draft","reviewed"),ev(2,"archive","reviewer","reviewed","archived")];
 const run=events=>reviewWorkflow({...base,traces:[{id:"t",initial_state:"draft",events}]});
 let passed=0;const check=(x,m)=>{if(!x)throw Error(m);passed++};
 check(run(good).totals.consistent===2,"valid workflow");
 check(run([ev(1,"archive","author","draft","archived")]).results[0].reasons.undeclared_accepted_transition===1,"undeclared transition");
 check(run([ev(1,"submit","author","draft","archived")]).results[0].reasons.unexpected_result_state===1,"incorrect state");
 check(run([ev(1,"submit","author","draft","reviewed","rejected")]).results[0].reasons.rejected_event_changed_state===1,"rejected change");
 check(run([good[0],ev(2,"archive","reviewer","draft","draft","rejected")]).results[0].reasons.state_discontinuity===1,"discontinuous record");
 check(run([good[0],{...good[1],sequence:3}]).totals.unknown===1,"missing record");
 check(run([{...good[0],observed_after:null}]).totals.unknown===1,"missing state");
 check(run([ev(1,"archive","author","draft",null)]).totals.inconsistent===1,"accepted undeclared transition with missing result");
 check(run([ev(1,"archive","author","draft",null,"rejected")]).totals.unknown===1,"missing rejected result");
 check(run([{...good[0],outcome:null}]).totals.unknown===1,"missing outcome");
 check(run([good[0],{...good[1],sequence:1}]).results[0].reasons.nonmonotonic_sequence===1,"duplicate sequence");
 check(run([]).status==="PARTIAL_REVIEW","empty trace");
 check(run([ev(1,"archive","author","draft","draft","rejected")]).totals.consistent===1,"rejection unchanged");
 let matrix=0;
 for(const from of base.states)for(const role of base.roles)for(const event of base.events)for(const to of base.states)for(const outcome of ["accepted","rejected"]){
  const expected=outcome==="rejected"?from===to:(from==="draft"&&role==="author"&&event==="submit"&&to==="reviewed")||(from==="reviewed"&&role==="reviewer"&&event==="archive"&&to==="archived");
  const r=reviewWorkflow({...base,traces:[{id:"m",initial_state:from,events:[ev(1,event,role,from,to,outcome)]}]});
  check(r.totals.consistent===Number(expected)&&r.totals.inconsistent===Number(!expected),"matrix");matrix++;
 }
 const invalids=[{...base,traces:[]},{...base,traces:[{id:"bad",initial_state:"invalid",events:[]}]},{...base,transitions:[base.transitions[0],base.transitions[0]],traces:[{id:"t",initial_state:"draft",events:[]}]},{...base,traces:[{id:"t",initial_state:"draft",events:[{...good[0],sequence:0}]}]}];
 for(const m of invalids){let rejected=false;try{reviewWorkflow(m)}catch{rejected=true}check(rejected,"invalid model")}
 return {passed,failed:0,synthetic_matrix_cases:matrix,scope:"authored local trace conformance only"};
}
if(require.main===module){try{const [cmd,file,flag]=process.argv.slice(2);if(cmd==="test")console.log(JSON.stringify(selftest(),null,2));else if(cmd==="review"&&file&&flag==="--authorized-local"){const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);try{const st=fs.fstatSync(fd);if(!st.isFile()||st.size>8*1024*1024)throw Error("Invalid file");const result=reviewWorkflow(JSON.parse(fs.readFileSync(fd,"utf8")));console.log(JSON.stringify(result,null,2));if(result.status!=="OBSERVED_TRACES_CONSISTENT")process.exitCode=3;}finally{fs.closeSync(fd)}}else throw Error("Invalid command");}catch{console.error("Local workflow review failed");process.exitCode=1;}}
module.exports={reviewWorkflow,selftest};
