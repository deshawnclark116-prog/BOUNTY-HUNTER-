'use strict';
const {reviewConditions}=require('../conditional-policy.js');
function challenge(review, supplyDomains=false){
 const L=literal=>({literal}),P=k=>({path:["context",k]}),cmp=(op,k,v)=>({op,left:P(k),right:L(v)}),eq=(k,v)=>cmp("eq",k,v);
 const and=(...args)=>({op:"and",args}),or=(...args)=>({op:"or",args}),not=arg=>({op:"not",arg});
 const member=(k,values)=>cmp("in",k,values);
 const rule=(id,effect,when,unless)=>({id,effect,role:"*",action:"*",resource:"*",when,...(unless?{unless}:{})});
 const allow=e=>rule("a","allow",e);
 const row=(id,context)=>({id,role:"employee",action:"read",resource:"record",attributes:{principal:{},resource:{},context},expected:null});
 const model=(rules,cases)=>({schema_version:2,environment:"local_policy_design",authorization:"owner_or_explicit_permission",rules,cases});
 // Domains are declared by the test oracle only; v0.11 receives no domain metadata.
 const domains={level:[-1,0,2,3,4,5,6,7,8,10,11],department:["sales","ops","finance","other"],active:[false,true]};
 const fields=Object.keys(domains);
 const product=(partial)=>fields.reduce((rows,k)=>rows.flatMap(x=>[...(partial?[x]:[]),...domains[k].map(v=>({...x,[k]:v}))]),[{}]);
 const inputs=product(true),worlds=product(false);
 const designs=[
  {name:"numeric_partition",rules:[allow(or(cmp("lt","level",5),cmp("gte","level",5)))],truth:x=>true},
  {name:"disjoint_numeric_ranges",rules:[allow(and(cmp("lt","level",3),cmp("gte","level",7)))],truth:x=>false},
  {name:"nested_numeric_interval",rules:[allow(and(cmp("gte","level",3),cmp("lte","level",7)))],truth:x=>x.level>=3&&x.level<=7},
  {name:"range_containment",rules:[rule("a","allow",cmp("gte","level",8)),rule("d","deny",cmp("gte","level",5))],truth:x=>false},
  {name:"distinct_departments",rules:[allow(and(eq("department","sales"),eq("department","ops")))],truth:x=>false},
  {name:"equality_complement",rules:[allow(or(eq("department","sales"),cmp("ne","department","sales")))],truth:x=>true},
  {name:"set_overlap",rules:[allow(and(member("department",["sales","ops"]),member("department",["finance","other"])))],truth:x=>false},
  {name:"set_subsumption",rules:[rule("a","allow",member("department",["sales"])),rule("d","deny",member("department",["sales","ops"]))],truth:x=>false},
  {name:"mixed_conditional",rules:[allow(and(eq("active",true),or(and(eq("department","sales"),cmp("gte","level",5)),and(eq("department","ops"),cmp("gte","level",3)))))],truth:x=>x.active&&((x.department==="sales"&&x.level>=5)||(x.department==="ops"&&x.level>=3))},
  {name:"conditional_exception",rules:[rule("a","allow",eq("active",true)),rule("d","deny",cmp("lt","level",5),eq("department","ops"))],truth:x=>x.active&&!(x.level<5&&x.department!=="ops")},
  {name:"identical_numeric_predicate",rules:[allow(and(cmp("gte","level",5),not(cmp("gte","level",5))))],truth:x=>false},
  {name:"numeric_equality_conflict",rules:[allow(and(eq("level",5),cmp("gt","level",5)))],truth:x=>false}
 ];
 const summary={designs:designs.length,cases:0,complete:0,complete_correct:0,definite_correct:0,necessary_unknown:0,avoidable_unknown_under_declared_domains:0,unsound_under_declared_domains:0,breakdown:[]};
 const rows=inputs.map((x,i)=>row("c"+i,x));
 for(const d of designs){
  const m=model(d.rules,rows);
  const output=review(supplyDomains?{...m,domains:Object.entries(domains).map(([k,values])=>({path:["context",k],values}))}:m);
  const tally={design:d.name,cases:inputs.length,definite:0,necessary_unknown:0,avoidable_unknown:0,unsound:0};
  for(let i=0;i<inputs.length;i++){
   const x=inputs[i],possible=new Set(worlds.filter(w=>Object.entries(x).every(([k,v])=>w[k]===v)).map(w=>d.truth(w)?"allow":"deny"));
   const expected=possible.size===1?[...possible][0]:"unknown",actual=output.results[i].decision;
   summary.cases++;
   if(Object.keys(x).length===fields.length){summary.complete++;if(actual===expected)summary.complete_correct++}
   if(actual===expected){if(actual==="unknown"){summary.necessary_unknown++;tally.necessary_unknown++}else{summary.definite_correct++;tally.definite++}}
   else if(actual==="unknown"){summary.avoidable_unknown_under_declared_domains++;tally.avoidable_unknown++}
   else{summary.unsound_under_declared_domains++;tally.unsound++}
  }
  summary.breakdown.push(tally);
 }
 return {...summary,scope:supplyDomains?"Development regression with explicit finite domains supplied.":"No-domain conservative baseline; oracle domains not supplied."};
}
const baseline=challenge(reviewConditions),candidate=challenge(reviewConditions,true);console.log(JSON.stringify({baseline,candidate},null,2));if(baseline.unsound_under_declared_domains||candidate.unsound_under_declared_domains||candidate.avoidable_unknown_under_declared_domains||candidate.complete_correct!==candidate.complete)process.exitCode=1;
