#!/usr/bin/env node
'use strict';
const path=require('node:path');
const {save}=require('./decode');
const {lift}=require('./vm');
const args=process.argv.slice(2);let out='out',inputs=[],vm=false,lua,max=5000;
for(let i=0;i<args.length;i++){
 const a=args[i];
 if(a==='-o'||a==='--out')out=args[++i];
 else if(a==='--vm')vm=true;
 else if(a==='--lua')lua=args[++i];
 else if(a==='--max')max=Number(args[++i]);
 else if(a==='-h'||a==='--help'){
   console.log('Usage: node cli.js [--vm] [--lua lua5.4] [--max 5000] [-o DIR] file1.lua [file2.lua ...]\n\n--vm additionally uses a Lua 5.3+ process to inspect the VM before target execution.\nThis is transport + VM instruction recovery, NOT full Lua source decompilation.');
   process.exit(0);
 } else if(a.startsWith('-')){console.error('Unknown option: '+a);process.exit(2)}
 else inputs.push(a);
}
if(inputs.length===0){console.error('Usage: node cli.js [--vm] -o out file.lua [file2.lua ...]');process.exit(2)}
let bad=false;
for(let i=0;i<inputs.length;i++){
 const input=path.resolve(inputs[i]);
 const dest=path.resolve(out,inputs.length===1?'payload':`depth-${i+1}`);
 try{
  const r=save(input,dest);
  console.log(`${path.basename(input)}: V11 header verified, extracted ${r.transportLengths.join(' + ')} bytes`);
  if(vm){
   const v=lift(input,dest,{lua,max});
   console.log(`  VM probe: ${v.instructions} instructions, builder ${v.builder.name}, written to ${dest}/vm-ir.txt`);
  }
  console.log('  Important: Devirtualization, control-flow reconstruction and ENCSTR recovery are not yet implemented.');
 }catch(e){bad=true;console.error(`${inputs[i]}: ${e.message}`)}
}
if(bad)process.exitCode=1;
