'use strict';
const {reviewConditions}=require('../conditional-policy.js');
function fresh(review){
 const L=literal=>({literal}),P=k=>({path:["context",k]}),op=(op,left,right)=>({op,left,right}),and=(...args)=>({op:"and",args}),or=(...args)=>({op:"or",args});
 const r=(id,effect,when,unless)=>({id,effect,role:"*",action:"*",resource:"*",when,...(unless?{unless}:{})});
 const row=(id,context)=>({id,role:"member",action:"read",resource:"record",attributes:{principal:{},resource:{},context},expected:null});
 const domains=[{path:["context","x"],values:[-2,0,1,4,8]},{path:["context","y"],values:[-1,0,2,4]},{path:["context","group"],values:["A","B","C"]}];
 const model=(rules,cases,d=domains)=>({schema_version:2,environment:"local_policy_design",authorization:"owner_or_explicit_permission",rules,cases,domains:d});
 const eq=(k,v)=>op("eq",P(k),L(v));
 const designs=[
 {rules:[r("a","allow",op("lt",P("x"),P("y"))),r("b","allow",op("gte",P("x"),P("y")))],truth:x=>true},
 {rules:[r("a","allow",op("gt",P("x"),P("y"))),r("d","deny",op("gte",P("x"),P("y")))],truth:x=>false},
 {rules:[r("a","allow",and(op("eq",P("x"),P("y")),op("gt",P("x"),P("y"))))],truth:x=>false},
 {rules:[r("a","allow",and(op("gte",P("x"),P("y")),or(eq("group","A"),eq("group","B"))))],truth:x=>x.x>=x.y&&x.group!=="C"},
 {rules:[r("a","allow",op("lte",P("x"),P("y"))),r("d","deny",eq("group","C"),op("eq",P("x"),P("y")))],truth:x=>x.x<=x.y&&!(x.group==="C"&&x.x!==x.y)},
 {rules:[r("a","allow",or(eq("group","A"),eq("group","B"),eq("group","C")))],truth:x=>true}
 ];
 const product=partial=>domains.reduce((rows,d)=>rows.flatMap(x=>[...(partial?[x]:[]),...d.values.map(v=>({...x,[d.path[1]]:v}))]),[{}]);
 const inputs=product(true),worlds=product(false),cases=inputs.map((x,i)=>row("c"+i,x));
 const out={designs:designs.length,cases:0,definite_correct:0,necessary_unknown:0,avoidable_unknown:0,unsound:0,guard_checks:0,guard_failures:0};
 for(const d of designs){
  const got=review(model(d.rules,cases));
  inputs.forEach((x,i)=>{
   const poss=new Set(worlds.filter(w=>Object.entries(x).every(([k,v])=>w[k]===v)).map(w=>d.truth(w)?"allow":"deny"));
   const expected=poss.size===1?[...poss][0]:"unknown",actual=got.results[i].decision;
   out.cases++;
   if(expected===actual){out[actual==="unknown"?"necessary_unknown":"definite_correct"]++}
   else out[actual==="unknown"?"avoidable_unknown":"unsound"]++;
  });
 }
 const check=b=>{out.guard_checks++;if(!b)out.guard_failures++};
 const reject=m=>{try{review(m);return false}catch{return true}};
 for(const d of [
  [{path:["context","x"],values:[1,"1"]}],
  [{path:["context","x"],values:[1,1]}],
  [{path:["context","x"],values:[]}],
  [{path:["context","x"],values:[1]},{path:["context","x","child"],values:[2]}],
  [{path:["context","constructor"],values:[1]}]
 ])check(reject(model([], [row("c",{})],d)));
 check(reject(model([], [row("c",{x:999})])));
 check(reject(model([], [row("c",{x:1})],[{path:["context","x","child"],values:[2]}])));
 check(review(model([r("a","allow",{op:"exists",value:P("x")})],[row("c",{})])).results[0].decision==="deny");
 check(review(model([r("a","allow",op("eq",P("x"),L(1)))],[row("c",{})])).results[0].decision==="unknown");
 check(review(model([r("a","allow",op("eq",P("x"),L(1)))],[row("c",{})],[])).results[0].decision==="unknown");
 const ds=["a","b","c"].map(k=>({path:["context",k],values:Array.from({length:7},(_,i)=>i)}));
 const e=or(...ds.map(d=>eq(d.path[1],0)));
 const limited=review(model([r("a","allow",e)],[row("c",{})],ds));
 check(limited.results[0].decision==="unknown"&&limited.results[0].reasoning==="domain_world_limit");
 return out;
}
const r=fresh(reviewConditions);console.log(JSON.stringify(r,null,2));if(r.unsound||r.avoidable_unknown||r.guard_failures)process.exitCode=1;
