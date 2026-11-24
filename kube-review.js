#!/usr/bin/env node
'use strict';
const fs=require('node:fs');
function audit(doc){
  const obj=(v,label)=>{if(!v||typeof v!=="object"||Array.isArray(v))throw Error("Invalid "+label);return v};
  const opt=(v,label)=>v==null?{}:obj(v,label);
  const arr=(v,label)=>{if(!Array.isArray(v))throw Error("Invalid "+label);return v};
  const bool=(v,label)=>{if(v!=null&&typeof v!=="boolean")throw Error("Invalid "+label);return v};
  const list=(v,label)=>v==null?[]:arr(v,label).map(x=>{if(typeof x!=="string")throw Error("Invalid "+label);return x});
  obj(doc,"manifest");
  const groups={Pod:["v1"],Deployment:["apps/v1"],StatefulSet:["apps/v1"],DaemonSet:["apps/v1"],ReplicaSet:["apps/v1"],Job:["batch/v1"],CronJob:["batch/v1"]};
  if(!Object.hasOwn(groups,doc.kind)||!groups[doc.kind].includes(doc.apiVersion))throw Error("Unsupported workload kind or API version");
  let s=doc.spec,base="spec";
  if(doc.kind==="CronJob"){s=s?.jobTemplate?.spec?.template?.spec;base+=".jobTemplate.spec.template.spec"}
  else if(doc.kind!=="Pod"){s=s?.template?.spec;base+=".template.spec"}
  obj(s,"pod spec");
  const p=opt(s.securityContext,"pod securityContext"),os=opt(s.os,"os").name;
  if(os!=null&&!["linux","windows"].includes(os))throw Error("Unsupported OS");
  const checks=[],skipped=[];
  function record(id,path,pass,fix){checks.push({id,path,result:pass?"pass":"policy_gap",remediation:pass?null:fix})}
  const ctx=(c,path)=>{
    for(const k of ["privileged","runAsNonRoot","allowPrivilegeEscalation"])bool(c[k],path+"."+k);
    if(c.runAsUser!=null&&(!Number.isSafeInteger(c.runAsUser)||c.runAsUser<0))throw Error("Invalid runAsUser");
    const w=opt(c.windowsOptions,"windowsOptions");bool(w.hostProcess,"hostProcess");
    const sec=opt(c.seccompProfile,"seccompProfile");if(sec.type!=null&&!["RuntimeDefault","Localhost","Unconfined"].includes(sec.type))throw Error("Invalid seccomp type");
    const cap=opt(c.capabilities,"capabilities");list(cap.add,"capabilities.add");list(cap.drop,"capabilities.drop");
    return {w,sec,cap};
  };
  const pp=ctx(p,base+".securityContext");
  for(const k of ["hostNetwork","hostPID","hostIPC"])record("HOST_NAMESPACE",base+"."+k,bool(s[k],k)!==true,"Disable host namespace sharing unless explicitly required.");
  record("HOST_PROCESS",base+".securityContext.windowsOptions.hostProcess",pp.w.hostProcess!==true,"Disable Windows HostProcess.");
  record("POD_NONROOT",base+".securityContext.runAsNonRoot",p.runAsNonRoot!==false,"Remove explicit false or require non-root.");
  record("POD_UID",base+".securityContext.runAsUser",p.runAsUser!==0,"Do not specify UID 0.");
  const vols=s.volumes==null?[]:arr(s.volumes,"volumes");
  const allowed=["configMap","csi","downwardAPI","emptyDir","ephemeral","persistentVolumeClaim","projected","secret"];
  for(let i=0;i<vols.length;i++){
    const v=obj(vols[i],"volume"),types=Object.keys(v).filter(k=>k!=="name"&&v[k]!=null);
    if(types.length!==1)throw Error("Volume must specify exactly one source");
    record("VOLUME_TYPE",base+".volumes["+i+"]",allowed.includes(types[0]),"Use a Restricted-profile volume type or document an exception.");
  }
  const linux=os!=="windows";
  if(linux)record("POD_SECCOMP",base+".securityContext.seccompProfile",pp.sec.type!=="Unconfined","Use RuntimeDefault or an approved Localhost profile.");
  for(const group of ["containers","initContainers","ephemeralContainers"]){
    const cs=group==="containers"?arr(s[group],group):s[group]==null?[]:arr(s[group],group);
    if(group==="containers"&&!cs.length)throw Error("No containers");
    for(let i=0;i<cs.length;i++){
      const c=obj(cs[i],"container"),q=opt(c.securityContext,"container securityContext"),path=base+"."+group+"["+i+"].securityContext",a=ctx(q,path);
      record("PRIVILEGED",path+".privileged",q.privileged!==true,"Set privileged to false or remove it.");
      record("HOST_PROCESS",path+".windowsOptions.hostProcess",a.w.hostProcess!==true,"Disable Windows HostProcess.");
      record("NONROOT",path+".runAsNonRoot",(q.runAsNonRoot??p.runAsNonRoot)===true,"Require non-root at container or pod level.");
      record("UID",path+".runAsUser",q.runAsUser!==0,"Do not specify UID 0.");
      if(!linux){skipped.push({path,reason:"Linux-specific escalation, seccomp and capabilities checks excluded for explicit Windows OS"});continue}
      record("ESCALATION",path+".allowPrivilegeEscalation",q.allowPrivilegeEscalation===false,"Set allowPrivilegeEscalation to false.");
      record("SECCOMP",path+".seccompProfile",["RuntimeDefault","Localhost"].includes(a.sec.type??pp.sec.type),"Set RuntimeDefault or an approved Localhost profile.");
      record("CAP_DROP",path+".capabilities.drop",list(a.cap.drop,"drop").includes("ALL"),"Drop ALL Linux capabilities.");
      record("CAP_ADD",path+".capabilities.add",list(a.cap.add,"add").every(x=>x==="NET_BIND_SERVICE"),"Remove added capabilities except NET_BIND_SERVICE if necessary.");
    }
  }
  return {kind:doc.kind,profile:"subset of Kubernetes Restricted Pod Security Standards",status:"STATIC_CONFIGURATION_REVIEW",checks,findings:checks.filter(x=>x.result==="policy_gap"),skipped,notice:"Declared manifest only; not a complete standards validator, runtime assessment, vulnerability proof or bounty claim. Verify deployment context before changes."};
}
function fixtures(){
 const clean={apiVersion:"v1",kind:"Pod",spec:{os:{name:"linux"},securityContext:{runAsNonRoot:true,runAsUser:1000,seccompProfile:{type:"RuntimeDefault"}},containers:[{name:"app",image:"example.invalid/app",securityContext:{allowPrivilegeEscalation:false,capabilities:{drop:["ALL"]}}}]}};
 const copy=()=>JSON.parse(JSON.stringify(clean));
 const cases=[];
 const add=(name,edit,expected,skip=0)=>{const m=copy();edit(m);cases.push({name,manifest:m,expected,skip})};
 const q=m=>m.spec.containers[0].securityContext;
 add("clean inheritance",()=>{},[]);
 add("allowed low port",m=>q(m).capabilities.add=["NET_BIND_SERVICE"],[]);
 add("host network",m=>m.spec.hostNetwork=true,["HOST_NAMESPACE"]);
 add("host PID and IPC",m=>{m.spec.hostPID=true;m.spec.hostIPC=true},["HOST_NAMESPACE","HOST_NAMESPACE"]);
 add("privileged",m=>q(m).privileged=true,["PRIVILEGED"]);
 add("explicit root UID",m=>q(m).runAsUser=0,["UID"]);
 add("pod root UID",m=>m.spec.securityContext.runAsUser=0,["POD_UID"]);
 add("container overrides nonroot",m=>q(m).runAsNonRoot=false,["NONROOT"]);
 add("pod false even with override",m=>{m.spec.securityContext.runAsNonRoot=false;q(m).runAsNonRoot=true},["POD_NONROOT"]);
 add("missing escalation",m=>delete q(m).allowPrivilegeEscalation,["ESCALATION"]);
 add("explicit escalation",m=>q(m).allowPrivilegeEscalation=true,["ESCALATION"]);
 add("unconfined override",m=>q(m).seccompProfile={type:"Unconfined"},["SECCOMP"]);
 add("pod unconfined despite override",m=>{m.spec.securityContext.seccompProfile={type:"Unconfined"};q(m).seccompProfile={type:"RuntimeDefault"}},["POD_SECCOMP"]);
 add("missing inherited seccomp",m=>delete m.spec.securityContext.seccompProfile,["SECCOMP"]);
 add("local profile",m=>q(m).seccompProfile={type:"Localhost",localhostProfile:"profiles/app.json"},[]);
 add("missing drop",m=>delete q(m).capabilities.drop,["CAP_DROP"]);
 add("extra capability",m=>q(m).capabilities.add=["NET_BIND_SERVICE","SYS_ADMIN"],["CAP_ADD"]);
 add("host path",m=>m.spec.volumes=[{name:"local",hostPath:{path:"/tmp"}}],["VOLUME_TYPE"]);
 add("empty dir",m=>m.spec.volumes=[{name:"temp",emptyDir:{}}],[]);
 add("init container checked",m=>m.spec.initContainers=[{name:"init",securityContext:{privileged:true,allowPrivilegeEscalation:false,capabilities:{drop:["ALL"]}}}],["PRIVILEGED"]);
 add("ephemeral container checked",m=>m.spec.ephemeralContainers=[{name:"debug",securityContext:{allowPrivilegeEscalation:true,capabilities:{drop:["ALL"]}}}],["ESCALATION"]);
 add("windows skip Linux rules",m=>{m.spec.os.name="windows";delete q(m).allowPrivilegeEscalation;delete q(m).capabilities;delete m.spec.securityContext.seccompProfile},[],1);
 add("windows host process",m=>{m.spec.os.name="windows";q(m).windowsOptions={hostProcess:true}},["HOST_PROCESS"],1);
 add("deployment template",m=>{m.kind="Deployment";m.apiVersion="apps/v1";m.spec={template:{spec:m.spec}}},[]);
 add("cronjob template",m=>{m.kind="CronJob";m.apiVersion="batch/v1";m.spec={jobTemplate:{spec:{template:{spec:m.spec}}}}},[]);
 return cases;
}
function selftest(){
 const cases=fixtures();let passed=0,expectedGaps=0;
 for(const c of cases){
   const r=audit(c.manifest);
   if(JSON.stringify(r.findings.map(x=>x.id).sort())!==JSON.stringify([...c.expected].sort())||r.skipped.length!==c.skip)throw Error("Fixture failed: "+c.name);
   passed++;expectedGaps+=c.expected.length;
 }
 let malformed=0;
 const invalid=[null,{}, {kind:"Secret",apiVersion:"v1",spec:{}},{kind:"Pod",apiVersion:"v1",spec:{containers:[]}},{kind:"Pod",apiVersion:"v1",spec:{hostNetwork:"true",containers:[{}]}},{kind:"Pod",apiVersion:"v1",spec:{containers:[{securityContext:{capabilities:{drop:"ALL"}}}]}}];
 for(const x of invalid){let rejected=false;try{audit(x)}catch{rejected=true}if(!rejected)throw Error("Malformed fixture accepted");malformed++}
 return {fixture_cases:cases.length,passed,expected_policy_gaps:expectedGaps,invalid_rejected:malformed,failed:0,scope:"authored regression fixtures, not independent holdout"};
}
if(require.main===module){
 try{
  const [cmd,file,flag]=process.argv.slice(2);
  if(cmd==="test")console.log(JSON.stringify(selftest(),null,2));
  else if(cmd==="audit"&&file&&flag==="--authorized-local"){
   const st=fs.lstatSync(file);
   if(!st.isFile()||st.size>2*1024*1024)throw Error("Regular local JSON file up to 2 MiB required");
   const result=audit(JSON.parse(fs.readFileSync(file,"utf8")));
   console.log(JSON.stringify(result,null,2));
   if(result.findings.length)process.exitCode=3;
  }else throw Error("Usage: node kube-review.js test | audit FILE --authorized-local");
 }catch(e){console.error(e.message);process.exitCode=1;}
}
module.exports={audit,fixtures,selftest};
