'use strict';
// Public benchmark translation only, specific to pinned Cedar sandbox_b examples.
// No general source extraction, application execution, or network interaction.
const fs=require('node:fs');
const path=require('node:path');
const {reviewConditions}=require('../conditional-policy.js');
const root=process.argv[2];
if(!root)throw Error("Pinned fixture root required");
const read=p=>JSON.parse(fs.readFileSync(path.join(root,p),'utf8'));
const key=x=>x.type+':'+x.id;
const entities=new Map(read('sample-data/sandbox_b/entities.json').map(e=>[key(e.uid),e]));
function member(u,target){
 const visited=new Set(),todo=[u];
 while(todo.length){const q=todo.pop();if(q===target)return true;if(visited.has(q))continue;visited.add(q);todo.push(...(entities.get(q)?.parents??[]).map(key))}
 return false;
}
const L=literal=>({literal}),P=(...path)=>({path});
const op=(op,left,right)=>({op,left,right});
const eq=(a,b)=>op('eq',a,b),and=(...args)=>({op:'and',args}),or=(...args)=>({op:'or',args}),not=arg=>({op:'not',arg});
const has=(...path)=>({op:'exists',value:P(...path)});
const bool=(root,attr)=>eq(P(root,attr),L(true));
const owner=and(has('resource','owner'),eq(P('principal','uid'),P('resource','owner')));
const ownPrivate=bool('resource','private');
const friend=bool('principal','aliceFriends');
const aliceAccount=bool('resource','aliceAccount');
const aliceAlbum=bool('resource','aliceAlbum');
const sales=eq(P('principal','department'),L('Sales'));
const auth=bool('context','authenticated');
const rule=(id,effect,action,when,unless)=>({id,effect,role:'*',resource:'*',action,...(when?{when}:{}),...(unless?{unless}:{})});
const definitions={
 'tests/multi/3.json':[
  rule('friends','allow','view',and(friend,aliceAccount)),
  rule('private','deny','*',ownPrivate,owner)],
 'tests/multi/4.json':[
  rule('friends','allow','view',and(friend,aliceAccount)),
  rule('sales','allow','*',and(sales,aliceAlbum)),
  rule('private','deny','*',ownPrivate,owner),
  rule('authentication','deny','*',not(auth))],
 'tests/multi/5.json':[
  rule('sales','allow','*',and(sales,aliceAlbum)),
  rule('authentication','deny','*',null,auth),
  rule('senior','allow','view',op('gte',P('principal','jobLevel'),L(7)))],
 'tests/example_use_cases/4a.json':[
  ...['listPhotos','view'].map((a,i)=>rule('engineering'+i,'allow',a,and(bool('resource','prototypes'),eq(P('principal','department'),L('HardwareEngineering')),op('gte',P('principal','jobLevel'),L(5)))))],
 'tests/example_use_cases/4d.json':[rule('owner','allow','*',owner)],
 'tests/example_use_cases/4e.json':[rule('department','allow','view',eq(P('principal','department'),P('resource','ownerDepartment')))],
 'tests/example_use_cases/4f.json':[rule('ownerOrAdmin','allow','*',or(owner,op('contains',P('resource','admins'),P('principal','uid'))))],
 'tests/example_use_cases/5b.json':[rule('upload','allow','addPhoto',and(aliceAccount,or(
  and(op('in',P('context','photo','filetype'),L(['JPEG','PNG'])),op('lte',P('context','photo','filesize_mb'),L(1))),
  and(eq(P('context','photo','filetype'),L('RAW')),op('lte',P('context','photo','filesize_mb'),L(100)),bool('principal','avTeam'))
 )))]
};
function attrs(req){
 const p=entities.get(key(req.principal)),r=entities.get(key(req.resource));
 if(!p||!r)throw Error('Missing fixture entity');
 const account=r.attrs.account&&entities.get(key(r.attrs.account));
 const o=account?.attrs.owner;
 const department=o&&entities.get(key(o))?.attrs.department;
 return {principal:{...p.attrs,uid:key(p.uid),aliceFriends:member(key(p.uid),'UserGroup:alice_friends'),avTeam:member(key(p.uid),'UserGroup:AVTeam')},
 resource:{...(typeof r.attrs.private==='boolean'?{private:r.attrs.private}:{}),...(o?{owner:key(o)}:{}),...(department!==undefined?{ownerDepartment:department}:{}),admins:(r.attrs.admins??[]).map(key),aliceAccount:member(key(r.uid),'Account:alice'),aliceAlbum:member(key(r.uid),'Album:alice_vacation'),prototypes:member(key(r.uid),'Album:device_prototypes')},
 context:req.context};
}
const totals={requests:0,correct:0,incorrect:0,unknown:0,allow:0,deny:0,suites:[]};
for(const [file,rules] of Object.entries(definitions)){
 const suite=read(file);
 if(suite.entities!=='sample-data/sandbox_b/entities.json')throw Error('Unexpected fixture data');
 const cases=suite.requests.map((req,i)=>{
  if(req.errors.length||!['allow','deny'].includes(req.decision))throw Error('Unsupported reference label');
  return {id:'case'+i,role:'user',resource:'fixture',action:req.action.id,attributes:attrs(req),expected:req.decision};
 });
 const result=reviewConditions({schema_version:2,environment:'local_policy_design',authorization:'owner_or_explicit_permission',rules,cases});
 totals.requests+=cases.length;totals.correct+=result.totals.correct;totals.incorrect+=result.totals.mismatches;totals.unknown+=result.totals.unknown;
 for(const c of cases)totals[c.expected]++;
 totals.suites.push({file,requests:cases.length,correct:result.totals.correct,incorrect:result.totals.mismatches,unknown:result.totals.unknown});
}
console.log(JSON.stringify(totals,null,2));
if(totals.incorrect||totals.unknown||totals.requests!==30)process.exitCode=1;
