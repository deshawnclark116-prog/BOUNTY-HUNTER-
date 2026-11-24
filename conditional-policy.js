'use strict';
const fs=require('node:fs');
function reviewConditions(model){
 const invalid=()=>{throw Error("Invalid conditional policy model")};
 const obj=x=>x!==null&&typeof x==="object"&&!Array.isArray(x);
 const own=(o,k)=>Object.prototype.hasOwnProperty.call(o,k);
 const identifier=x=>typeof x==="string"&&/^[A-Za-z][A-Za-z0-9_-]{0,47}$/.test(x);
 const safeKey=x=>identifier(x)&&!["__proto__","constructor","prototype"].includes(x);
 const fields=(x,allowed,required=allowed)=>{if(!obj(x)||Object.keys(x).some(k=>!allowed.includes(k))||required.some(k=>!own(x,k)))invalid()};
 const scalar=x=>typeof x==="boolean"||(typeof x==="number"&&Number.isFinite(x))||(typeof x==="string"&&x.length<=1024);
 const value=x=>scalar(x)||(Array.isArray(x)&&x.length<=64&&x.every(scalar));
 const roots=["principal","resource","context"];
 const dims=["role","action","resource"];
 if(!obj(model)||model.schema_version!==2||model.environment!=="local_policy_design"||model.authorization!=="owner_or_explicit_permission")invalid();
 fields(model,["schema_version","environment","authorization","rules","cases"]);
 if(!Array.isArray(model.rules)||model.rules.length>200||!Array.isArray(model.cases)||model.cases.length<1||model.cases.length>2000)invalid();
 let nodes=0,attributeNodes=0;
 const missing=Symbol("missing");
 const U=null;
 function attrTree(x,depth=0){
  if(++attributeNodes>100000||depth>10)invalid();
  if(value(x))return;
  if(!obj(x)||Object.keys(x).length>64)invalid();
  for(const [k,v] of Object.entries(x)){if(!safeKey(k))invalid();attrTree(v,depth+1)}
 }
 function operand(o){
  if(!obj(o)||Object.keys(o).length!==1)invalid();
  if(own(o,"literal")){if(!value(o.literal))invalid();return}
  if(!own(o,"path")||!Array.isArray(o.path)||o.path.length<2||o.path.length>10||!roots.includes(o.path[0])||o.path.slice(1).some(k=>!safeKey(k)))invalid();
 }
 function validate(e,depth=0){
  if(++nodes>12000||depth>12||!obj(e))invalid();
  if(["and","or"].includes(e.op)){fields(e,["op","args"]);if(!Array.isArray(e.args)||e.args.length<1||e.args.length>32)invalid();e.args.forEach(x=>validate(x,depth+1));return}
  if(e.op==="not"){fields(e,["op","arg"]);validate(e.arg,depth+1);return}
  if(e.op==="exists"){fields(e,["op","value"]);operand(e.value);if(!own(e.value,"path"))invalid();return}
  if(["eq","ne","lt","lte","gt","gte","contains","in"].includes(e.op)){fields(e,["op","left","right"]);operand(e.left);operand(e.right);return}
  invalid();
 }
 function get(o,attrs){
  if(own(o,"literal"))return o.literal;
  let v=attrs;
  for(const k of o.path){if(!obj(v)||!own(v,k))return missing;v=v[k]}
  return v;
 }
 function all(xs){return xs.includes(false)?false:xs.includes(U)?U:true}
 function any(xs){return xs.includes(true)?true:xs.includes(U)?U:false}
 const not=x=>x===U?U:!x;
 function evaluate(e,attrs){
  if(e.op==="and")return all(e.args.map(x=>evaluate(x,attrs)));
  if(e.op==="or")return any(e.args.map(x=>evaluate(x,attrs)));
  if(e.op==="not")return not(evaluate(e.arg,attrs));
  if(e.op==="exists")return get(e.value,attrs)!==missing;
  const l=get(e.left,attrs),r=get(e.right,attrs);
  if(l===missing||r===missing)return U;
  if(e.op==="eq"||e.op==="ne"){
   if(!scalar(l)||!scalar(r)||typeof l!==typeof r)return U;
   return e.op==="eq"?l===r:l!==r;
  }
  if(e.op==="contains"||e.op==="in"){
   const [list,item]=e.op==="contains"?[l,r]:[r,l];
   if(!Array.isArray(list)||!scalar(item)||!list.every(scalar))return U;
   return list.some(x=>typeof x===typeof item&&x===item);
  }
  if(typeof l!=="number"||typeof r!=="number")return U;
  return ({lt:l<r,lte:l<=r,gt:l>r,gte:l>=r})[e.op];
 }
 const rules=new Set();
 for(const r of model.rules){
  fields(r,["id","role","action","resource","effect","when","unless"],["id","role","action","resource","effect"]);
  if(!identifier(r.id)||rules.has(r.id)||!["allow","deny"].includes(r.effect)||dims.some(k=>r[k]!=="*"&&!identifier(r[k])))invalid();
  rules.add(r.id);
  for(const k of ["when","unless"])if(own(r,k))validate(r[k]);
 }
 const caseIds=new Set();
 for(const c of model.cases){
  fields(c,["id","role","action","resource","attributes","expected"]);
  if(!identifier(c.id)||caseIds.has(c.id)||dims.some(k=>!identifier(c[k]))||!["allow","deny",null].includes(c.expected))invalid();
  caseIds.add(c.id);
  fields(c.attributes,roots);
  if(roots.some(k=>!obj(c.attributes[k])))invalid();
  attrTree(c.attributes);
 }
 const totals={cases:model.cases.length,decided:0,unknown:0,unlabeled:0,compared:0,correct:0,mismatches:0,overgrant:0,undergrant:0,conflicts:0};
 const results=[];
 for(const c of model.cases){
  const permits=[],denials=[];
  for(const r of model.rules){
   if(!dims.every(k=>r[k]==="*"||r[k]===c[k]))continue;
   const match=all([own(r,"when")?evaluate(r.when,c.attributes):true,own(r,"unless")?not(evaluate(r.unless,c.attributes)):true]);
   (r.effect==="allow"?permits:denials).push(match);
  }
  const a=any(permits),d=any(denials);
  // Conservative three-valued review: never silently treat missing data as false.
  const decision=d===true||a===false?"deny":a===true&&d===false?"allow":"unknown";
  if(decision==="unknown")totals.unknown++;else totals.decided++;
  if(a===true&&d===true)totals.conflicts++;
  let status;
  if(c.expected===null){totals.unlabeled++;status="no_contract"}
  else if(decision==="unknown")status="needs_information";
  else{totals.compared++;if(c.expected===decision){totals.correct++;status="match"}else{totals.mismatches++;totals[decision==="allow"?"overgrant":"undergrant"]++;status="model_mismatch"}}
  results.push({case_id:c.id,decision,status,conflict:a===true&&d===true});
 }
 return {status:totals.unknown||totals.unlabeled?"PARTIAL_MODEL_REVIEW":"COMPLETE_MODEL_REVIEW",totals,results,notice:"Owner-supplied local policy cases only. Unknown inputs abstain; explicit deny overrides permit. No actual application behavior or exploitability verified. Attributes are not echoed."};
}
function selftest(){
 const literal=x=>({literal:x}),p=(...path)=>({path});
 const eq=(left,right)=>({op:"eq",left,right});
 const rule=(id,effect,when)=>({id,effect,role:"*",action:"*",resource:"*",when});
 const row=(id,attrs,expected)=>({id,role:"employee",action:"read",resource:"record",attributes:{principal:{},resource:{},context:{},...attrs},expected});
 const model=(rules,cases)=>({schema_version:2,environment:"local_policy_design",authorization:"owner_or_explicit_permission",rules,cases});
 const t=eq(literal(true),literal(true)),f=eq(literal(true),literal(false)),u=eq(p("context","missing"),literal(true));
 let passed=0;const check=(x,m)=>{if(!x)throw Error(m);passed++};
 const states=[t,f,u],names=["true","false","unknown"];
 // All nine combinations; manually specified decision table.
 const answers=[["deny","allow","unknown"],["deny","deny","deny"],["deny","unknown","unknown"]];
 for(let a=0;a<3;a++)for(let d=0;d<3;d++){
  const r=reviewConditions(model([rule("permit","allow",states[a]),rule("forbid","deny",states[d])],[row("case",{},null)]));
  check(r.results[0].decision===answers[a][d],names[a]+"/"+names[d]);
 }
 const composite={op:"and",args:[eq(p("principal","department"),p("resource","department")),{op:"gte",left:p("principal","level"),right:literal(5)},eq(p("context","authenticated"),literal(true))]};
 const cases=[row("approved",{principal:{department:"A",level:5},resource:{department:"A"},context:{authenticated:true}},"allow"),row("otherdept",{principal:{department:"B",level:6},resource:{department:"A"},context:{authenticated:true}},"deny"),row("lowlevel",{principal:{department:"A",level:4},resource:{department:"A"},context:{authenticated:true}},"deny"),row("unknownlevel",{principal:{department:"A"},resource:{department:"A"},context:{authenticated:true}},"allow")];
 const r=reviewConditions(model([rule("qualified","allow",composite)],cases));
 check(r.totals.correct===3&&r.totals.unknown===1,"department and threshold");
 check(r.status==="PARTIAL_MODEL_REVIEW","unknown not complete");
 const expressions=[
 [{op:"or",args:[t,u]},"allow"],[{op:"or",args:[f,u]},"unknown"],[{op:"and",args:[f,u]},"deny"],[{op:"and",args:[t,u]},"unknown"],[{op:"not",arg:u},"unknown"],
 [{op:"contains",left:literal(["A","B"]),right:literal("B")},"allow"],
 [{op:"in",left:literal(1),right:literal(["1"])},"deny"],
 [eq(literal("1"),literal(1)),"unknown"],[{op:"gte",left:literal("5"),right:literal(3)},"unknown"],
 [{op:"exists",value:p("resource","owner")},"deny"],
 [{op:"and",args:[{op:"exists",value:p("resource","owner")},eq(p("resource","owner"),literal("A"))]},"deny"]
 ];
 for(const [e,expected] of expressions)check(reviewConditions(model([rule("r","allow",e)],[row("c",{},null)])).results[0].decision===expected,"expression "+e.op);
 const exception={...rule("r","allow",t),unless:u};
 check(reviewConditions(model([exception],[row("c",{},null)])).results[0].decision==="unknown","missing exception");
 check(reviewConditions(model([rule("r","allow",t),rule("d","deny",t)],[row("c",{},"allow")])).totals.undergrant===1,"deny priority");
 check(reviewConditions(model([rule("r","allow",t)],[row("c",{},"deny")])).totals.overgrant===1,"unexpected allow");
 const payloads=[{op:"execute"},eq({path:["principal","constructor"]},literal("x")),{op:"and",args:[]},{op:"not",arg:{op:"bad"}},eq({literal:{x:1}},literal("x"))];
 for(const e of payloads){let rejected=false;try{reviewConditions(model([rule("r","allow",e)],[row("c",{},null)]))}catch{rejected=true}check(rejected,"invalid expression rejected")}
 const badCases=[row("bad",{principal:{constructor:"x"}},null),row("bad",{context:{a:Infinity}},null)];
 for(const c of badCases){let rejected=false;try{reviewConditions(model([], [c]))}catch{rejected=true}check(rejected,"invalid attributes rejected")}
 const good=model([rule("r","allow",t)],[row("c",{context:{privateNote:"SECRET_FIXTURE"}},null)]);
 check(!JSON.stringify(reviewConditions(good)).includes("SECRET_FIXTURE"),"attributes not echoed");
 return {passed,failed:0,scope:"authored local conditional model tests"};
}
if(require.main===module){try{const [cmd,file,flag]=process.argv.slice(2);if(cmd==="test")console.log(JSON.stringify(selftest(),null,2));else if(cmd==="review"&&file&&flag==="--authorized-local"){const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);try{const st=fs.fstatSync(fd);if(!st.isFile()||st.size>2*1024*1024)throw Error("Invalid file");const result=reviewConditions(JSON.parse(fs.readFileSync(fd,"utf8")));console.log(JSON.stringify(result,null,2));if(result.status==="PARTIAL_MODEL_REVIEW")process.exitCode=3;}finally{fs.closeSync(fd)}}else throw Error("Invalid command");}catch{console.error("Local conditional model review failed");process.exitCode=1;}}
module.exports={reviewConditions,selftest};
