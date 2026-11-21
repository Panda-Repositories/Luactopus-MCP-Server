'use strict';
const fs=require('node:fs');
const path=require('node:path');
const child=require('node:child_process');

function detectProtoBuilder(source) {
 const re=/return\s+\{((?:\[(?:0x\w+|\d+)\]\s*=.{1,110}?,?){4,})\};end/g;
 let m;
 while((m=re.exec(source))!==null) {
  const keys=[...m[1].matchAll(/\[(0x\w+|\d+)\]\s*=/g)].map(x=>x[1]);
  if(keys.length!==6||keys.filter(k=>k.startsWith('0x')).length<5)continue;
  // V11 prototype constructors store their lazy instruction stream in slot 3.
  const propertyRE=/\["([a-zA-Z0-9_]+)"\]\s*=\s*\(*function\s*\(/g;
  let prop,last;
  while((prop=propertyRE.exec(source.slice(0,m.index)))!==null)last=prop;
  if(!last || m.index-last.index>600)continue;
  return {name:last[1],instructionKey:Number(keys[2]),fields:keys.map(Number)};
 }
 throw Error('Could not identify V11 prototype builder');
}
function executable(candidate) {
 const p=child.spawnSync(candidate,['--version'],{encoding:'utf8',timeout:1600});
 return !p.error;
}
function lift(input,destination, opts={}) {
 const src=fs.readFileSync(input,'utf8');
 const builder=detectProtoBuilder(src);
 const lua=opts.lua||['lua','lua5.4','lua5.3','texlua'].find(executable);
 if(!lua)throw Error('VM inspection requires Lua 5.3+ or texlua; use --lua /path/to/lua');
 const worker=path.join(__dirname,'vm_probe.lua');
 const outfile=path.join(destination,'vm-ir.json');
 const max=Math.min(Math.max(Number(opts.max)||5000,1),50000);
 const res=child.spawnSync(lua,[worker,input,builder.name,String(builder.instructionKey),String(max),outfile],{
  encoding:'utf8',timeout:opts.timeout||15000,maxBuffer:1000000,windowsHide:true
 });
 if(res.error)throw Error(`VM extraction failed: ${res.error.message}`);
 if(res.status!==0)throw Error('VM extractor error: '+(res.stderr||res.stdout).slice(0,600));
 const data=JSON.parse(fs.readFileSync(outfile,'utf8'));
 if(data.status!=='captured'||!data.prototypes.length)throw Error(`VM extraction incomplete: ${data.status}`);
 const lines=[
  '-- GOOFYSCATOR V11 DISASSEMBLY / IR',
  '-- This is NOT reconstructed Lua source.',
  '-- Instruction operands and handler names are obfuscated; execution was NOT performed.',
  `-- Prototype builder: ${builder.name} | VM instruction slot: ${builder.instructionKey}`,
  ''
 ];
 for(let p=0;p<data.prototypes.length;p++){
  const proto=data.prototypes[p];
  lines.push(`-- PROTOTYPE ${p+1}: ${proto.records.length} decoded VM instruction records`);
  for(const row of proto.records){
   if(row.error){lines.push(`-- ${row.pc}: DECODE ERROR ${row.error}`);continue;}
   lines.push(`${String(row.pc).padStart(5,'0')}  ${row.handler.padEnd(16)} ${JSON.stringify(row.raw)}`);
  }
 }
 fs.writeFileSync(path.join(destination,'vm-ir.txt'),lines.join('\n')+'\n');
 return {lua,builder,prototypes:data.prototypes.length,instructions:data.prototypes.reduce((n,p)=>n+p.records.length,0),status:data.status};
}
module.exports={detectProtoBuilder,lift};
