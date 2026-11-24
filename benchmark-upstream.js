'use strict';
const fs=require('node:fs');
const {audit}=require('./kube-review.js');
function score(rows){
 const seen=new Set(),details=[];
 let tp=0,tn=0,fp=0,fn=0,errors=0;
 for(const row of rows){
  if(!row||typeof row.id!=='string'||seen.has(row.id)||typeof row.expectedFail!=='boolean')throw Error('Invalid or duplicate benchmark case');
  seen.add(row.id);
  try{
   const result=audit(row.manifest);
   const ids=[...new Set(result.findings.map(x=>x.id))];
   const predictedFail=ids.length>0;
   const outcome=row.expectedFail?(predictedFail?'tp':'fn'):(predictedFail?'fp':'tn');
   if(outcome==='tp')tp++;else if(outcome==='tn')tn++;else if(outcome==='fp')fp++;else fn++;
   details.push({id:row.id,expectedFail:row.expectedFail,outcome,ids});
  }catch(e){errors++;details.push({id:row.id,expectedFail:row.expectedFail,outcome:'error',message:e.message});}
 }
 const positives=rows.filter(x=>x.expectedFail).length,negatives=rows.length-positives;
 if(!positives||!negatives)throw Error('Independent suite must contain both pass and fail cases');
 const precision=tp+fp?tp/(tp+fp):null;
 const recall=tp/positives; // include failed-to-evaluate positive cases as misses
 const coverage=(rows.length-errors)/rows.length;
 return {total:rows.length,positives,negatives,tp,tn,fp,fn,errors,precision,recall,coverage,
  specificity:tn/negatives,
  gate:rows.length>=100&&precision!==null&&precision>=.95&&recall>=.80&&coverage===1?'NUMERIC_TARGETS_MET':'NOT_MET',
  note:'Pod-level agreement with upstream Restricted policy labels, not proof of vulnerability discovery. The auditor implements a subset, so unsupported controls count as misses. Repeated fixtures can share a common base and are not independent statistical samples.',details};
}
if(require.main===module){
 try{
  const rows=JSON.parse(fs.readFileSync(process.argv[2],'utf8'));
  if(!Array.isArray(rows))throw Error('Expected array');
  console.log(JSON.stringify(score(rows),null,2));
 }catch(e){console.error(e.message);process.exitCode=1;}
}
module.exports={score};
