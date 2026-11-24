'use strict';
function dependencyReview(lock, snapshot) {
  const object=(x,label)=>{if(!x||typeof x!=="object"||Array.isArray(x))throw Error("Invalid "+label);return x};
  const semver=x=>typeof x==="string"&&/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(x)?x.split(".").map(BigInt):null;
  const cmp=(a,b)=>{for(let i=0;i<3;i++){if(a[i]<b[i])return -1;if(a[i]>b[i])return 1}return 0};
  const validName=x=>typeof x==="string"&&/^(?:@[a-z0-9._-]+\/)?[a-z0-9._-]+$/i.test(x);
  object(lock,"lockfile");object(snapshot,"advisory snapshot");
  if(![2,3].includes(lock.lockfileVersion))throw Error("npm package-lock version 2 or 3 required");
  const packages=object(lock.packages,"lockfile packages");
  if(typeof snapshot.source!=="string"||!snapshot.source.trim()||typeof snapshot.as_of!=="string"||!Number.isFinite(Date.parse(snapshot.as_of))||!Array.isArray(snapshot.advisories))throw Error("Snapshot source, date and advisory array required");
  const byName=new Map(), ids=new Set();
  for(const a of snapshot.advisories){
    object(a,"advisory");
    if(typeof a.id!=="string"||!a.id.trim()||ids.has(a.id)||!Array.isArray(a.affected))throw Error("Invalid or duplicate advisory");
    ids.add(a.id);
    if(a.withdrawn)continue;
    for(const entry of a.affected){
      object(entry,"affected entry");const p=object(entry.package,"affected package");
      if(p.ecosystem!=="npm")continue;
      if(!validName(p.name))throw Error("Invalid advisory package name");
      if(!byName.has(p.name))byName.set(p.name,[]);
      byName.get(p.name).push({id:a.id,entry});
    }
  }
  function evaluate(entry,version){
    const v=semver(version);
    if(!v)return {match:false,unknown:true};
    let match=false,unknown=false;
    if(entry.versions!=null){
      if(!Array.isArray(entry.versions)||entry.versions.some(x=>typeof x!=="string"))throw Error("Invalid explicit versions");
      match=entry.versions.includes(version);
    }
    if(entry.ranges!=null&&!Array.isArray(entry.ranges))throw Error("Invalid ranges");
    for(const range of entry.ranges??[]){
      object(range,"range");
      if(!["SEMVER","ECOSYSTEM"].includes(range.type)||!Array.isArray(range.events)||!range.events.length){unknown=true;continue}
      let active=false,lower=null,last=null,rangeMatch=false,bad=false;
      for(const e of range.events){
        object(e,"range event");const keys=Object.keys(e);
        if(keys.length!==1){bad=true;break}
        const type=keys[0],value=e[type],bound=type==="introduced"&&value==="0"?[0n,0n,0n]:semver(value);
        if(!bound||(last&&cmp(bound,last)<0)){bad=true;break}
        last=bound;
        if(type==="introduced"){
          if(active){bad=true;break}
          lower=bound;active=true;
        }else if(["fixed","last_affected","limit"].includes(type)){
          if(!active){bad=true;break}
          const upper=cmp(v,bound);
          if(cmp(v,lower)>=0&&(type==="last_affected"?upper<=0:upper<0))rangeMatch=true;
          active=false;
        }else{bad=true;break}
      }
      if(bad){unknown=true;continue}
      if(active&&cmp(v,lower)>=0)rangeMatch=true;
      match=match||rangeMatch;
    }
    if(!(entry.versions?.length||entry.ranges?.length))unknown=true;
    return {match,unknown};
  }
  const findings=[],unknown=[],counts={inventory:0,evaluated:0,matched_packages:0,no_snapshot_match:0,unknown:0};
  for(const [path,p] of Object.entries(packages)){
    if(path==="")continue;
    counts.inventory++;object(p,"package entry");
    const parts=path.split("node_modules/"),name=p.name??parts[parts.length-1];
    if(p.link||!path.includes("node_modules/")||!validName(name)||!semver(p.version)){
      unknown.push({package:validName(name)?name:null,reason:"Unsupported package identity, link or version"});counts.unknown++;continue;
    }
    const matches=new Set();let uncertain=false;
    for(const a of byName.get(name)??[]){
      const r=evaluate(a.entry,p.version);if(r.match)matches.add(a.id);if(r.unknown)uncertain=true;
    }
    if(matches.size){counts.matched_packages++;for(const id of [...matches].sort())findings.push({package:name,version:p.version,advisory:id,status:"known_advisory_match",action:"Review the official advisory and update to an unaffected supported version; retest the application."})}
    if(uncertain){unknown.push({package:name,reason:"Unsupported advisory interval or incomplete range"});counts.unknown++}
    else{counts.evaluated++;if(!matches.size)counts.no_snapshot_match++}
  }
  return {snapshot_as_of:snapshot.as_of,advisories_considered:ids.size,counts,findings,unknown,notice:"Local inventory comparison only. Snapshot completeness and freshness are not verified; no match does not mean safe. Stable npm versions only. Matches are known advisories, not novel discoveries or proof of exploitability."};
}
function selftest(){
  let n=0;const check=(x,msg)=>{if(!x)throw Error(msg);n++};
  const make=(version,name="demo")=>({lockfileVersion:3,packages:{"":{},["node_modules/"+name]:{version}}});
  const snapshot=(events,type="SEMVER")=>({source:"synthetic",as_of:"2026-11-23",advisories:[{id:"TEST-1",affected:[{package:{ecosystem:"npm",name:"demo"},ranges:[{type,events}]}]}]});
  const s=snapshot([{introduced:"0"},{fixed:"2.0.0"}]);
  check(dependencyReview(make("1.9.9"),s).findings.length===1,"affected");
  check(dependencyReview(make("2.0.0"),s).findings.length===0,"fixed boundary");
  check(dependencyReview(make("10.0.0"),s).findings.length===0,"numeric version");
  check(dependencyReview(make("1.0.0","other"),s).findings.length===0,"different package");
  check(dependencyReview(make("1.0.0-beta.1"),s).counts.unknown===1,"prerelease abstains");
  check(dependencyReview(make("2.0.0"),snapshot([{introduced:"1.0.0"},{last_affected:"2.0.0"}])).findings.length===1,"inclusive boundary");
  check(dependencyReview(make("2.0.0"),snapshot([{introduced:"1.0.0"},{limit:"2.0.0"}])).findings.length===0,"exclusive limit");
  check(dependencyReview(make("3.0.0"),snapshot([{introduced:"2.0.0"}])).findings.length===1,"open interval");
  check(dependencyReview(make("2.5.0"),snapshot([{introduced:"0"},{fixed:"2.0.0"},{introduced:"3.0.0"}])).findings.length===0,"between intervals");
  check(dependencyReview(make("1.0.0"),snapshot([{introduced:"0"},{fixed:"2.0.0"}],"GIT")).counts.unknown===1,"unsupported range");
  check(dependencyReview(make("1.0.0"),snapshot([{fixed:"2.0.0"}])).counts.unknown===1,"broken interval");
  check(dependencyReview(make("1.0.0"),{...s,advisories:[{...s.advisories[0],withdrawn:"2025-01-01"}]}).findings.length===0,"withdrawn advisory");
  return {passed:n,failed:0};
}
if(require.main===module)console.log(JSON.stringify(selftest(),null,2));
module.exports={dependencyReview,selftest};
