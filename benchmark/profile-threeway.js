'use strict';
// Benchmark only: local policy evaluation on a fixed public documentation example.
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const {spawnSync}=require('node:child_process');
const {reviewConditions}=require('../conditional-policy.js');
const doc=fs.readFileSync(process.argv[2],'utf8');
function block(name){
 const marker='\x60\x60\x60rego title="'+name+'"';
 const start=doc.indexOf(marker),from=doc.indexOf('\n',start)+1,end=doc.indexOf('\n\x60\x60\x60',from);
 if(start<0||end<0)throw Error('Pinned doc block missing');
 return doc.slice(from,end);
}
function run(command,args){
 const r=spawnSync(command,args,{encoding:'utf8',timeout:30000,maxBuffer:4*1024*1024});
 if(r.status!==0)throw Error(command+' failed: '+r.stderr+' '+r.stdout);
 return r.stdout;
}
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'profile-policy-'));
try{
 const policy=path.join(dir,'example.rego'),tests=path.join(dir,'example_test.rego'),wrapper=path.join(dir,'wrapper.rego'),inputFile=path.join(dir,'cases.json');
 fs.writeFileSync(policy,block('example.rego'));
 fs.writeFileSync(tests,block('example_test.rego'));
 const upstream=JSON.parse(run('opa',['test','--format=json',policy,tests]));
 if(upstream.length!==4||upstream.some(x=>x.fail||x.error||x.skip))throw Error('Published OPA tests not verified');
 // Published labels are fixed; generated variations are separate and not independent labels.
 const rows=[
  {input:{path:['users'],method:'POST'},expected:'allow',kind:'documented'},
  {input:{path:['users'],method:'GET'},expected:'deny',kind:'documented'},
  {input:{path:['users','bob'],method:'GET',user_id:'bob'},expected:'allow',kind:'documented'},
  {input:{path:['users','bob'],method:'GET',user_id:'alice'},expected:'deny',kind:'documented'}
 ];
 const seen=new Set(rows.map(x=>JSON.stringify(x.input)));
 for(const p of [[],['users'],['users','bob'],['users','alice'],['users','bob','extra'],['other','bob']])
 for(const method of ['GET','POST','PUT','DELETE'])
 for(const user_id of ['alice','bob','charlie',undefined]){
  const input={path:p,method,...(user_id===undefined?{}:{user_id})};
  if(!seen.has(JSON.stringify(input)))rows.push({input,expected:null,kind:user_id===undefined?'generated_missing_identity':'generated_complete'});
 }
 const normalize=x=>({kind:x.path.length===1&&x.path[0]==='users'?'collection':x.path.length===2&&x.path[0]==='users'?'profile':'other',owner:x.path[1]??''});
 const rules=[
  {id:'create',role:'*',action:'POST',resource:'collection',effect:'allow'},
  {id:'own',role:'*',action:'GET',resource:'profile',effect:'allow',when:{op:'eq',left:{path:['principal','name']},right:{path:['resource','owner']}}}
 ];
 const cases=rows.map((r,i)=>{const n=normalize(r.input);return {id:'case'+i,role:'user',action:r.input.method,resource:n.kind,attributes:{principal:r.input.user_id===undefined?{}:{name:r.input.user_id},resource:{owner:n.owner},context:{}},expected:r.expected}});
 const result=reviewConditions({schema_version:2,environment:'local_policy_design',authorization:'owner_or_explicit_permission',rules,cases});
 // OPA's example has undefined rather than explicit false for unmatched inputs.
 // Normalize undefined to deny exactly as its published tests do.
 fs.writeFileSync(wrapper,'package comparison\nallowed(c) if { data.authz.allow with input as c }\ndefault allowed(c) := false\nresults := {sprintf("%d", [i]): d | some i; c := input[i]; d := allowed(c)}\n');
 fs.writeFileSync(inputFile,JSON.stringify(rows.map(r=>r.input)));
 const opa=JSON.parse(run('opa',['eval','--format=json','--input',inputFile,'--data',policy,'--data',wrapper,'data.comparison.results'])).result?.[0]?.expressions?.[0]?.value;
 if(!opa||Object.keys(opa).length!==rows.length)throw Error('Incomplete OPA output');
 const casbin=JSON.parse(run('python3',[path.join(__dirname,'casbin-profile.py'),inputFile]));
 if(casbin.length!==rows.length)throw Error('Incomplete Casbin output');
 const stats={total:rows.length,published_opa_tests:upstream.length,documented:0,documented_correct:{ours:0,opa:0,casbin:0},generated:0,all_three_agree:0,ours_unknown:0,definite_disagreements:0,reference_disagreements:0,by_kind:{}};
 rows.forEach((r,i)=>{
  const a=result.results[i].decision,b=opa[String(i)]?'allow':'deny',c=casbin[i]?'allow':'deny';
  const g=stats.by_kind[r.kind]??={total:0,agree:0,unknown:0,disagree:0};
  g.total++;
  if(b!==c)stats.reference_disagreements++;
  if(a==='unknown'){stats.ours_unknown++;g.unknown++}
  else if(a===b&&a===c){stats.all_three_agree++;g.agree++}
  else{stats.definite_disagreements++;g.disagree++}
  if(r.kind==='documented'){stats.documented++;for(const [k,v] of Object.entries({ours:a,opa:b,casbin:c}))if(v===r.expected)stats.documented_correct[k]++}
  else stats.generated++;
 });
 stats.coverage=(stats.total-stats.ours_unknown)/stats.total;
 console.log(JSON.stringify(stats,null,2));
 // Unknown is reported, not silently promoted to deny or removed from coverage.
 if(stats.definite_disagreements||stats.reference_disagreements||Object.values(stats.documented_correct).some(x=>x!==stats.documented))process.exitCode=1;
}finally{fs.rmSync(dir,{recursive:true,force:true})}
