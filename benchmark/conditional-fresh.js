'use strict';
const {reviewConditions}=require('../conditional-policy.js');
function fresh(review){
 const keys=["a","b","c","d"], L=literal=>({literal});
 const atom=k=>({op:"eq",left:{path:["context",k]},right:L(true)});
 const model=(rules,cases)=>({schema_version:2,environment:"local_policy_design",authorization:"owner_or_explicit_permission",rules,cases});
 const row=(id,context)=>({id,role:"member",action:"read",resource:"record",attributes:{principal:{},resource:{},context},expected:null});
 const rule=(id,effect,when,unless)=>({id,effect,role:"*",action:"*",resource:"*",when,...(unless?{unless}:{})});
 let seed=0x195fe77c;
 const rnd=n=>{seed^=seed<<13;seed^=seed>>>17;seed^=seed<<5;return (seed>>>0)%n};
 // Generate expression and truth mask together using bitwise operations, not the verifier.
 const atoms=keys.map((k,i)=>({expr:atom(k),mask:Array.from({length:16},(_,j)=>j).reduce((m,j)=>m|((j>>i&1)<<j),0)}));
 function expr(depth){
  if(!depth||rnd(4)===0)return atoms[rnd(4)];
  const a=expr(depth-1),op=rnd(3);
  if(op===0)return {expr:{op:"not",arg:a.expr},mask:(~a.mask)&65535};
  const b=expr(depth-1);
  return {expr:{op:op===1?"and":"or",args:[a.expr,b.expr]},mask:op===1?a.mask&b.mask:a.mask|b.mask};
 }
 const partials=keys.reduce((a,k)=>a.flatMap(x=>[x,{...x,[k]:true},{...x,[k]:false}]),[{}]);
 const cases=partials.map((p,i)=>row("c"+i,p));
 const result={designs:40,cases:0,correct_definite:0,necessary_unknown:0,avoidable_unknown:0,unsound:0,allow:0,deny:0,guard_checks:0,guard_failures:0};
 for(let i=0;i<40;i++){
  let permits=0,denials=0;const rules=[];
  for(let j=0;j<2+rnd(4);j++){
   const a=expr(4),b=rnd(2)?expr(3):null,effect=rnd(2)?"allow":"deny";
   const mask=a.mask&(b?~b.mask:65535);
   if(effect==="allow")permits|=mask;else denials|=mask;
   rules.push(rule("r"+j,effect,a.expr,b?.expr));
  }
  const truth=permits&~denials&65535;
  const actual=review(model(rules,cases));
  for(let k=0;k<partials.length;k++){
   let possible=0;
   for(let j=0;j<16;j++)if(Object.entries(partials[k]).every(([key,v])=>Boolean(j>>keys.indexOf(key)&1)===v))possible|=1<<j;
   const expected=(truth&possible)===0?"deny":(truth&possible)===possible?"allow":"unknown";
   const got=actual.results[k].decision;
   result.cases++;
   if(got===expected){if(got==="unknown")result.necessary_unknown++;else{result.correct_definite++;result[got]++}}
   else if(got==="unknown")result.avoidable_unknown++;else result.unsound++;
  }
 }
 const check=(v)=>{result.guard_checks++;if(!v)result.guard_failures++};
 const a=atom("a");
 const many={op:"or",args:Array.from({length:9},(_,i)=>atom("x"+i))};
 check(review(model([rule("r","allow",many)],[row("c",{})])).results[0].decision==="unknown");
 check(review(model([rule("r","allow",a)],[row("c",{a:"yes"})])).results[0].decision==="unknown");
 const exists={op:"exists",value:{path:["context","a"]}};
 check(review(model([rule("r","allow",exists)],[row("c",{})])).results[0].decision==="deny");
 check(review(model([rule("r","allow",a)],[row("c",{})])).results[0].decision==="unknown");
 return result;
}
const r=fresh(reviewConditions);console.log(JSON.stringify(r,null,2));if(r.unsound||r.avoidable_unknown||r.guard_failures)process.exitCode=1;
