'use strict';
const {auditPolicy}=require('../policy-model.js');
function benchmark(audit){
  const dims=["role","action","resource","relationship","auth"];
  const base={schema_version:1,environment:"local_policy_design",authorization:"owner_or_explicit_permission",roles:["reader","editor","admin"],actions:["read","write","delete"],resources:["record","invoice"],rules:[],contract:[]};
  function domain(m){return [m.roles,m.actions,m.resources,["own","same_tenant","other_tenant"],["authenticated","anonymous"]]}
  function product(axes){return axes.reduce((rows,values)=>rows.flatMap(row=>values.map(v=>[...row,v])),[[]])}
  function key(row){return JSON.stringify(dims.map(k=>row[k]))}
  function row(v){return Object.fromEntries(dims.map((k,i)=>[k,v[i]]))}
  function oracle(m){
    const axes=domain(m);
    const permits=new Set(),denials=new Set();
    for(const rule of m.rules){
      const set=rule.effect==="allow"?permits:denials;
      const selected=axes.map((values,i)=>rule[dims[i]]==="*"?values:[rule[dims[i]]]);
      for(const v of product(selected))set.add(JSON.stringify(v));
    }
    const contract=new Map(m.contract.map(c=>[key(c),c.expected]));
    const findings=new Set();
    let unknown=0,over=0,under=0,conflicts=0,matches=0;
    for(const v of product(axes)){
      const k=JSON.stringify(v),a=permits.has(k),d=denials.has(k);
      if(a&&d){conflicts++;findings.add(k+"overlapping_rules")}
      const expected=contract.get(k);
      if(expected===undefined){unknown++;continue}
      const actual=a&&!d?"allow":"deny";
      if(actual===expected)matches++;
      else if(actual==="allow"){over++;findings.add(k+"contract_overgrant")}
      else{under++;findings.add(k+"contract_undergrant")}
    }
    return {findings,unknown,over,under,conflicts,matches};
  }
  let seed=0x21edcba1;
  const rnd=n=>{seed=(Math.imul(seed,1664525)+1013904223)>>>0;return (seed>>>8)%n};
  let models=0,states=0,covered=0,unknown=0,over=0,under=0,conflicts=0,matches=0, failures=0;
  let orderChecks=0;
  const failureExamples=[];
  function evaluate(m,label,order=false){
    const e=oracle(m),a=audit(m);
    const actual=new Set(a.findings.map(r=>key(r)+r.type));
    const t=a.totals;
    const expectedStates=product(domain(m)).length;
    const correct=actual.size===e.findings.size&&[...actual].every(x=>e.findings.has(x))&&t.evaluated===expectedStates&&t.contract_unknown===e.unknown&&t.unintended_grants===e.over&&t.missing_grants===e.under&&t.conflicts===e.conflicts&&t.contract_matches===e.matches&&t.contract_covered===m.contract.length&&a.status===(e.unknown?"PARTIAL_MODEL_REVIEW":"COMPLETE_MODEL_REVIEW");
    models++;states+=expectedStates;covered+=m.contract.length;unknown+=e.unknown;over+=e.over;under+=e.under;conflicts+=e.conflicts;matches+=e.matches;
    if(!correct){failures++;if(failureExamples.length<10)failureExamples.push(label)}
    if(order){orderChecks++;const b=audit({...m,rules:[...m.rules].reverse()});if(JSON.stringify(a.totals)!==JSON.stringify(b.totals)||JSON.stringify(a.findings)!==JSON.stringify(b.findings)){failures++;failureExamples.push(label+":order")}}
  }
  // Independent set-expansion oracle; synthetic designs generated after the engine was frozen.
  for(let i=0;i<300;i++){
    const m={...base,rules:[],contract:[]};
    const axes=domain(m);
    const ruleCount=1+rnd(36);
    for(let j=0;j<ruleCount;j++){
      const values=axes.map(d=>rnd(4)===0?"*":d[rnd(d.length)]);
      m.rules.push({id:"r"+j,...row(values),effect:rnd(2)?"allow":"deny"});
    }
    for(const v of product(axes))if(rnd(7)!==0)m.contract.push({...row(v),expected:rnd(2)?"allow":"deny"});
    evaluate(m,"generated-"+i,i%10===0);
  }
  // Independently documented Cedar README example, translated to this restricted model.
  // Only two documented decisions are labeled. Remaining states stay unknown.
  const cedar={...base,roles:["alice"],actions:["view"],resources:["vacation_photo","secret_photo"],rules:[{id:"vacation",role:"alice",action:"view",resource:"vacation_photo",relationship:"*",auth:"authenticated",effect:"allow"}],contract:[
    {role:"alice",action:"view",resource:"vacation_photo",relationship:"other_tenant",auth:"authenticated",expected:"allow"},
    {role:"alice",action:"view",resource:"secret_photo",relationship:"other_tenant",auth:"authenticated",expected:"deny"}]};
  evaluate(cedar,"cedar-doc-translation");
  const c=audit(cedar);
  const documented={correct:c.totals.contract_matches,total:2,unknown:c.totals.contract_unknown,source:"https://github.com/cedar-policy/cedar#quick-start"};
  const max={...base,roles:Array.from({length:10},(_,i)=>"r"+i),actions:Array.from({length:16},(_,i)=>"a"+i),resources:Array.from({length:16},(_,i)=>"p"+i),rules:[],contract:[]};
  // All 15,360 states must be examined; only the first 200 explicit rules are admitted.
  for(const v of product(domain(max)))max.contract.push({...row(v),expected:"deny"});
  for(let i=0;i<200;i++)max.rules.push({id:"rule"+i,...row([max.roles[i%10],max.actions[i%16],max.resources[(i*7)%16],"own","authenticated"]),effect:"deny"});
  const start=Date.now();evaluate(max,"max-size");const max_ms=Date.now()-start;
  const malformed=[
    null,{...base,authorization:"unknown"},{...base,environment:"live"},{...base,roles:[]},{...base,roles:["a","a"]},{...base,actions:Array.from({length:17},(_,i)=>"a"+i)},
    {...base,rules:[{id:"bad",effect:"allow",role:"missing",action:"*",resource:"*",relationship:"*",auth:"*"}]},
    {...base,contract:[{...row(["reader","read","record","own","authenticated"]),expected:"unknown"}]},
    {...base,rules:Array.from({length:201},(_,i)=>({id:"r"+i,effect:"deny",role:"*",action:"*",resource:"*",relationship:"*",auth:"*"}))},
    {...base,contract:Array.from({length:20001},()=>({}))}
  ];
  let rejected=0;for(const m of malformed){try{audit(m)}catch{rejected++}}
  return {synthetic_and_translated_models:models,states_examined:states,contract_covered:covered,unknown_contract_states:unknown,oracle_agreement_models:models-failures,failures,failureExamples,expected_overgrants:over,expected_undergrants:under,expected_conflicts:conflicts,expected_matches:matches,rule_order_checks:orderChecks,malformed_rejected:rejected,malformed_total:malformed.length,documented_examples:documented,max_size_states:15360,max_size_comparison_ms:max_ms,note:"Synthetic differential tests against a separately implemented set-expansion oracle; two manually translated documented Cedar decisions. Not independent real-world vulnerability discovery."};
}
const results=benchmark(auditPolicy);
console.log(JSON.stringify(results,null,2));
if(!results.expected_conflicts||!results.expected_overgrants||!results.expected_undergrants||results.failures||results.malformed_rejected!==results.malformed_total||results.documented_examples.correct!==results.documented_examples.total)process.exitCode=1;
