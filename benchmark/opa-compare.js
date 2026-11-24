'use strict';
// Fixed public documentation example only; offline decision conformance, no application or network tests.
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const {spawnSync}=require('node:child_process');
const {reviewConditions}=require('../conditional-policy.js');
const doc=fs.readFileSync(process.argv[2],'utf8');
const block=name=>{
 const marker='\x60\x60\x60rego title="'+name+'"';
 const start=doc.indexOf(marker);
 if(start<0)throw Error('Pinned documentation block missing');
 const from=doc.indexOf('\n',start)+1,end=doc.indexOf('\n\x60\x60\x60',from);
 if(end<0)throw Error('Incomplete code block');
 return doc.slice(from,end);
};
const tmp=fs.mkdtempSync(path.join(os.tmpdir(),'policy-comparison-'));
const L=literal=>({literal}),P=(...path)=>({path});
const eq=(left,right)=>({op:'eq',left,right});
const roles={alice:[],charlie:[],bob:['alice'],betty:['charlie'],david:[],visitor:[]};
const people=Object.keys(roles);
const rule=(id,when)=>({id,role:'*',resource:'salary',action:'GET',effect:'allow',when});
const rules=[rule('self',eq(P('principal','name'),P('resource','owner'))),rule('manager',{op:'contains',left:P('principal','reports'),right:P('resource','owner')})];
const hr=rule('hr',eq(P('principal','name'),L('david')));
const examples=[
 {stage:'base',user:'alice',target:'alice',expected:true},
 {stage:'base',user:'bob',target:'alice',expected:true},
 {stage:'base',user:'bob',target:'charlie',expected:false},
 ...['alice','bob','charlie','david'].map(target=>({stage:'hr',user:'david',target,expected:true}))
];
function input(user,target,method,resource){return {user,method,path:resource==='salary'?['finance','salary',target]:['other',target]}}
function compare(stage,policyFiles){
 const documented=examples.filter(x=>x.stage===stage).map(x=>({...x,method:'GET',resource:'salary',kind:'documented'}));
 const seen=new Set(documented.map(x=>JSON.stringify(input(x.user,x.target,x.method,x.resource))));
 const generated=[];
 for(const user of people)for(const target of people)for(const method of ['GET','POST','PUT'])for(const resource of ['salary','other']){
  if(!seen.has(JSON.stringify(input(user,target,method,resource))))generated.push({user,target,method,resource,kind:'generated'});
 }
 const rows=[...documented,...generated],cases=rows.map((x,i)=>({id:'c'+i,role:'employee',action:x.method,resource:x.resource,attributes:{principal:{name:x.user,reports:roles[x.user]},resource:{owner:x.target},context:{}},expected:x.kind==='documented'?(x.expected?'allow':'deny'):null}));
 const start=process.hrtime.bigint();
 const ours=reviewConditions({schema_version:2,environment:'local_policy_design',authorization:'owner_or_explicit_permission',rules:stage==='hr'?[...rules,hr]:rules,cases});
 const our_ms=Number(process.hrtime.bigint()-start)/1e6;
 const inputFile=path.join(tmp,'input.json');fs.writeFileSync(inputFile,JSON.stringify(rows.map(x=>input(x.user,x.target,x.method,x.resource))));
 const wrapper=path.join(tmp,'compare.rego');
 fs.writeFileSync(wrapper,'package comparison\nresults := {sprintf("%d", [i]): d | some i; c := input[i]; d := data.httpapi.authz.allow with input as c}\n');
 const args=['eval','--format=json','--input',inputFile,...[...policyFiles,wrapper].flatMap(p=>['--data',p]),'data.comparison.results'];
 const run=spawnSync('opa',args,{encoding:'utf8',timeout:30000,maxBuffer:4*1024*1024});
 if(run.status!==0)throw Error('OPA comparison failed: '+run.stderr);
 const obj=JSON.parse(run.stdout).result?.[0]?.expressions?.[0]?.value;
 if(!obj||Object.keys(obj).length!==rows.length)throw Error('Incomplete OPA output');
 const result={stage,documented:documented.length,generated:generated.length,ours_correct_documented:0,opa_correct_documented:0,agreement:0,disagreement:0,unknown:0,opa_allow:0,opa_deny:0,our_ms};
 rows.forEach((x,i)=>{
  const ref=obj[String(i)],decision=ours.results[i].decision;
  if(typeof ref!=='boolean')throw Error('Nonboolean OPA output');
  result[ref?'opa_allow':'opa_deny']++;
  if(decision==='unknown')result.unknown++;
  else if((decision==='allow')===ref)result.agreement++;else result.disagreement++;
  if(x.kind==='documented'){if(ref===x.expected)result.opa_correct_documented++;if(decision===(x.expected?'allow':'deny'))result.ours_correct_documented++}
 });
 return result;
}
try{
 const base=path.join(tmp,'example.rego'),extension=path.join(tmp,'example-hr.rego');
 fs.writeFileSync(base,block('example.rego'));fs.writeFileSync(extension,block('example-hr.rego'));
 const results=[compare('base',[base]),compare('hr',[base,extension])];
 console.log(JSON.stringify({reference:'OPA v1.4.2, pinned public HTTP API authorization documentation',results,note:'Generated cases measure agreement, not independent ground truth. Seven documented labels measure conformance. Not vulnerability discovery or general OPA equivalence.'},null,2));
 if(results.some(r=>r.disagreement||r.unknown||r.ours_correct_documented!==r.documented||r.opa_correct_documented!==r.documented))process.exitCode=1;
}finally{fs.rmSync(tmp,{recursive:true,force:true})}
