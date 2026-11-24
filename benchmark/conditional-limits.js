'use strict';
const {reviewConditions}=require('../conditional-policy.js');
function stress(review){
 const P=k=>({path:["context",k]}),L=literal=>({literal}),b=k=>({op:"eq",left:P(k),right:L(true)});
 const and=(...args)=>({op:"and",args}),or=(...args)=>({op:"or",args}),not=arg=>({op:"not",arg});
 const rule=(id,effect,when,unless)=>({id,effect,role:"*",action:"*",resource:"*",...(when?{when}:{}),...(unless?{unless}:{})});
 const row=(id,context,expected=null)=>({id,role:"member",action:"read",resource:"record",attributes:{principal:{},resource:{},context},expected});
 const model=(rules,cases)=>({schema_version:2,environment:"local_policy_design",authorization:"owner_or_explicit_permission",rules,cases});
 const designs=[
 {name:"membership_and_approval",rules:[rule("allow","allow",and(b("member"),or(b("owner"),b("approved")),b("active"))),rule("deny","deny",b("suspended"))],oracle:x=>x.member&&(x.owner||x.approved)&&x.active&&!x.suspended},
 {name:"exception_requires_approval",rules:[rule("allow","allow",or(b("owner"),b("approved"))),rule("deny","deny",b("suspended"),and(b("member"),b("active")))],oracle:x=>(x.owner||x.approved)&&!(x.suspended&&!(x.member&&x.active))},
 {name:"correlated_partition",rules:[rule("a","allow",and(b("member"),b("active"))),rule("b","allow",and(b("member"),not(b("active"))))],oracle:x=>x.member},
 {name:"mutually_exclusive_conditions",rules:[rule("a","allow",and(b("member"),not(b("member"))))],oracle:()=>false},
 {name:"dependent_permit_and_deny",rules:[rule("a","allow",b("member")),rule("d","deny",b("member"))],oracle:()=>false},
 {name:"nested_conditions",rules:[rule("a","allow",and(or(b("member"),b("owner")),not(and(b("suspended"),not(b("approved")))),b("active")))],oracle:x=>(x.member||x.owner)&&!(x.suspended&&!x.approved)&&x.active}
 ];
 const fields=["member","owner","approved","active","suspended"];
 const partials=fields.reduce((a,k)=>a.flatMap(x=>[x,{...x,[k]:true},{...x,[k]:false}]),[{}]);
 const completions=fields.reduce((a,k)=>a.flatMap(x=>[{...x,[k]:true},{...x,[k]:false}]),[{}]);
 let count=0,definite=0,necessary=0,excess=0,wrong=0,complete=0,completeCorrect=0;const breakdown=[];
 for(const d of designs){
  const cases=partials.map((x,i)=>row("c"+i,x));
  const result=review(model(d.rules,cases));
  const tally={design:d.name,total:cases.length,definite_correct:0,necessary_unknown:0,avoidable_unknown:0,wrong:0,fully_specified:0,fully_specified_correct:0};
  for(let i=0;i<cases.length;i++){
   const x=partials[i];
   const possibilities=new Set(completions.filter(y=>Object.entries(x).every(([k,v])=>y[k]===v)).map(y=>d.oracle(y)?"allow":"deny"));
   const expected=possibilities.size===1?[...possibilities][0]:"unknown";
   const actual=result.results[i].decision;
   count++;
   if(actual===expected){if(actual==="unknown"){necessary++;tally.necessary_unknown++}else{definite++;tally.definite_correct++}}
   else if(actual==="unknown"){excess++;tally.avoidable_unknown++}
   else{wrong++;tally.wrong++}
   if(Object.keys(x).length===fields.length){complete++;tally.fully_specified++;if(actual===expected){completeCorrect++;tally.fully_specified_correct++}}
  }
  breakdown.push(tally);
 }
 const maxRules=Array.from({length:200},(_,i)=>rule("r"+i,i%2?"deny":"allow",and(b("active"),or(b("owner"),b("approved")))));
 const maxCases=Array.from({length:2000},(_,i)=>row("c"+i,{active:i%2===0,owner:i%4===0,approved:i%8===0},"deny"));
 const start=Date.now();const max=review(model(maxRules,maxCases));const elapsed=Date.now()-start;
 const expectedConflicts=maxCases.filter(c=>c.attributes.context.active&&(c.attributes.context.owner||c.attributes.context.approved)).length;
 const maxOk=max.totals.correct===2000&&max.totals.conflicts===expectedConflicts&&max.totals.unknown===0;
 const deep=Array.from({length:200},(_,i)=>rule("r"+i,"allow",and(...Array.from({length:29},()=>and(b("active"))))));
 const deepCases=Array.from({length:100},(_,i)=>row("c"+i,{active:i%2===0},i%2===0?"allow":"deny"));
 const ds=Date.now();const large=review(model(deep,deepCases));const deepElapsed=Date.now()-ds;
 const invalids=[
  model([],[]),model(Array.from({length:201},(_,i)=>rule("r"+i,"allow",b("active"))),[row("c",{})]),
  model([],Array.from({length:2001},(_,i)=>row("c"+i,{}))),
  model([rule("r","allow",and(...Array.from({length:33},()=>b("active"))))],[row("c",{})]),
  model([rule("r","allow",Array.from({length:13}).reduce(x=>not(x),b("active")))],[row("c",{})]),
  model([rule("r","allow",b("active")),rule("r","deny",b("active"))],[row("c",{})]),
  model([], [row("c",{}),row("c",{})]),
  model([], [row("c",{value:"x".repeat(1025)})]),
  model([], [row("c",{values:Array.from({length:65},()=>1)})]),
  model([], [row("c",{value:null})]),
  model([rule("r","allow",{op:"eq",left:{path:["context","prototype"]},right:L(1)})],[row("c",{})]),
  model([], [row("c",JSON.parse('{"__proto__":true}'))])
 ];
 let rejected=0;for(const m of invalids){try{review(m)}catch{rejected++}}
 return {scope:"synthetic, independently expressed truth functions and completion oracle for bounded local policy models",logical_cases:count,fully_specified:{total:complete,correct:completeCorrect},definite_correct:definite,necessary_unknown:necessary,avoidable_unknown:excess,unsound_decisions:wrong,breakdown,maximum_dimensions:{rules:200,cases:2000,rule_case_pairs:400000,expected_conflicts:expectedConflicts,observed_conflicts:max.totals.conflicts,correct:max.totals.correct,elapsed_ms:elapsed,passed:maxOk},expression_budget:{rules:200,expression_nodes:11800,cases:100,correct:large.totals.correct,elapsed_ms:deepElapsed},invalid_models:{total:invalids.length,rejected}};
}
const r=stress(reviewConditions);console.log(JSON.stringify(r,null,2));if(r.unsound_decisions||r.fully_specified.correct!==r.fully_specified.total||!r.maximum_dimensions.passed||r.expression_budget.correct!==r.expression_budget.cases||r.invalid_models.rejected!==r.invalid_models.total)process.exitCode=1;
