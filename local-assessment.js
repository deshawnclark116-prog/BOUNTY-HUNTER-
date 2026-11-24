'use strict';
const fs=require('node:fs');
const {audit}=require('./kube-review.js');
const {dependencyReview}=require('./dependency-review.js');
const {assessment}=require('./remediation.js');
function review(bundle){
  if(!bundle||bundle.authorization!=="owner_or_explicit_permission"||bundle.schema_version!==1)throw Error("Authorized local assessment schema v1 required");
  const sections={};
  const run=(name,input,fn)=>{
    if(input===undefined){sections[name]={status:"not_assessed"};return}
    try{sections[name]={status:"reviewed",result:fn(input)}}catch{sections[name]={status:"evaluation_error",reason:"Malformed or unsupported input; review privately."}}
  };
  run("kubernetes",bundle.kubernetes,docs=>{
    if(!Array.isArray(docs)||docs.length===0||docs.length>200)throw Error("Invalid manifest collection");
    const results=docs.map((doc,index)=>{try{return {index,status:"reviewed",...audit(doc)}}catch{return {index,status:"evaluation_error"}}});
    return {manifests:docs.length,errors:results.filter(r=>r.status==="evaluation_error").length,policy_gaps:results.reduce((n,r)=>n+(r.findings?.length??0),0),results};
  });
  run("npm_dependencies",bundle.npm,x=>dependencyReview(x.lockfile,x.snapshot));
  run("remediation",bundle.remediation,x=>assessment(x));
  const incomplete=Object.values(sections).some(s=>s.status!=="reviewed")||
    (sections.kubernetes.result?.errors??0)>0||(sections.npm_dependencies.result?.counts.unknown??0)>0;
  return {schema_version:1,status:incomplete?"PARTIAL_REVIEW":"LOCAL_REVIEW_COMPLETE",sections,
    notice:"No overall security rating. Unassessed areas remain unknown. Known advisory matches and policy gaps require contextual review. No network, application execution or submission."};
}
function selftest(){
 let passed=0;const check=(ok,msg)=>{if(!ok)throw Error(msg);passed++};
 const base={schema_version:1,authorization:"owner_or_explicit_permission"};
 const x=review(base);
 check(x.status==="PARTIAL_REVIEW","Empty input cannot pass");
 check(x.sections.npm_dependencies.status==="not_assessed","Missing dependency input");
 const bad=review({...base,kubernetes:[{}]});
 check(bad.sections.kubernetes.result.errors===1,"Invalid manifest tracked");
 check(bad.status==="PARTIAL_REVIEW","Invalid manifest prevents complete");
 const broken=review({...base,npm:{}});
 check(broken.sections.npm_dependencies.status==="evaluation_error","Invalid dependency input");
 let blocked=false;try{review({...base,authorization:"unknown"})}catch{blocked=true}
 check(blocked,"Reject missing authorization");
 const good=review({...base,kubernetes:[{apiVersion:"v1",kind:"Pod",spec:{containers:[{name:"demo",image:"demo"}]}}],npm:{lockfile:{lockfileVersion:3,packages:{"":{}}},snapshot:{source:"synthetic",as_of:"2026-11-23",advisories:[]}},remediation:{authorization:"owner_or_explicit_permission",as_of:"2026-11-23",records:[]}});
 check(good.status==="LOCAL_REVIEW_COMPLETE","Complete workflow");
 check(good.sections.kubernetes.result.policy_gaps>0,"Gaps remain visible");
 return {passed,failed:0};
}
if(require.main===module){
 try{
  const [cmd,file,flag]=process.argv.slice(2);
  if(cmd==="test")console.log(JSON.stringify(selftest(),null,2));
  else if(cmd==="review"&&file&&flag==="--authorized-local"){
   const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);
   try{const st=fs.fstatSync(fd);if(!st.isFile()||st.size>20*1024*1024)throw Error("Regular local JSON file <=20 MiB required");const result=review(JSON.parse(fs.readFileSync(fd,"utf8")));console.log(JSON.stringify(result,null,2));if(result.status==="PARTIAL_REVIEW")process.exitCode=3;}
   finally{fs.closeSync(fd)}
  }else throw Error("Usage: node local-assessment.js test | review FILE --authorized-local");
 }catch(e){console.error("Local review failed: "+(e instanceof SyntaxError?"Invalid JSON":e.message));process.exitCode=1;}
}
module.exports={review,selftest};
