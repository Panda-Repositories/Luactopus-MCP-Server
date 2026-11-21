#!/usr/bin/env node
'use strict';

// Goofyscator V11: one stable entry point for the existing Discord bot.
// This is dynamic behavioral recovery, NOT complete VM devirtualization.
// The requested Lua output is always written when the input is readable.
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const cp = require('node:child_process');
const {unpack} = require('./decode.js');

const HELP = `Usage: node deobf.js input.lua [-o deobfuscated.lua] [--lua lua] [--lune lune]
       node deobf.js --batch file1.lua file2.lua -o recovered

Always writes a .lua file for each readable input.
If source recovery is partial it writes the best observed trace to that same file.
If no recoverable events are observed, it retains the original protected Lua
in the output and marks it INCOMPLETE rather than creating an empty file.
Use --engine lua, --engine lune, or --engine auto (default).
`;

const argv = process.argv.slice(2);
let output = 'deobfuscated.lua', luaBinary = null, luneBinary = 'lune',
    engine = 'auto', batch = false;
const inputs = [];
for(let i=0;i<argv.length;i++) {
  const t=argv[i];
  if(t==='-o'||t==='--output') output=argv[++i];
  else if(t==='--lua') luaBinary=argv[++i];
  else if(t==='--lune') luneBinary=argv[++i];
  else if(t==='--engine') engine=argv[++i];
  else if(t==='--batch') batch=true;
  else if(t==='--help'||t==='-h') {console.log(HELP); process.exit(0)}
  else if(t.startsWith('-')) {console.error('Unknown option: '+t+'\n'+HELP);process.exit(2)}
  else inputs.push(t);
}
if(!inputs.length || (!batch && inputs.length!==1) ||
   !['auto','lua','lune'].includes(engine) ||
   !output || (argv.includes('-o') && !argv[argv.indexOf('-o')+1])) {
  console.error(HELP); process.exit(2);
}

const checker=path.join(__dirname,'syntax_check.lua');
const luaProbe=path.join(__dirname,'capture_effects.lua');
const luneProbe=path.join(__dirname,'lune_probe.luau');
const runtime = (bin, args, timeout=25000) => cp.spawnSync(bin,args,{
  encoding:'utf8', windowsHide:true, timeout, maxBuffer:16*1024*1024
});
function luaCandidate() {
  for(const bin of (luaBinary ? [luaBinary] : ['lua','lua5.4','lua5.3','texlua'])) {
    const r=runtime(bin,[checker,checker],6000);
    if(!r.error && r.status===0 && /COMPILES/.test(r.stdout||'')) return bin;
  }
  return null;
}
function isUsableLua(source) {
  return typeof source==='string' && source.trim().length>0 &&
    /(?:^|\n)\s*(?:local\s+\w+\s*=|(?:print|warn)\s*\(|\w+[.:][\w.]+\s*=|\w+[.:][\w.]+:Connect\(|return\b)/m.test(source);
}
function score(source) {
  const count=(pattern)=>(source.match(pattern)||[]).length;
  return count(/Instance\.new\s*\(/g)*15 +
    count(/:Connect\s*\(/g)*12 +
    count(/(?:print|warn)\s*\(/g)*3 +
    count(/^\s*\w+\.\w+\s*=/gm)*2 +
    count(/^\s*return\s+/gm);
}
function safeComment(text) {
  return String(text).replace(/[\r\n]+/g,' ').replace(/[\x00-\x1f]/g,'').slice(0,400);
}
function luaRun(bin, file) {
  const result=runtime(bin,[luaProbe,file],28000);
  const body=result.stdout||'';
  return {
    engine:'Lua '+bin, body,
    note:safeComment((result.stderr||result.error?.message||'').trim()),
    incomplete:!!result.error || result.status!==0 || /trace-warning:/.test(result.stderr||''),
    failed:!!result.error || result.status!==0
  };
}
function luneRun(bin, file) {
  const temp=fs.mkdtempSync(path.join(os.tmpdir(),'goofy-v11-'));
  try {
    const trace=path.join(temp,'trace.lua');
    const result=runtime(bin,['run',luneProbe,file,trace],25000);
    return {
      engine:'Lune '+bin,
      body:fs.existsSync(trace)?fs.readFileSync(trace,'utf8'):'',
      note:safeComment((result.stderr||result.stdout||result.error?.message||'').trim()),
      incomplete:!!result.error || result.status!==0,
      failed:!!result.error || result.status!==0
    };
  } finally { fs.rmSync(temp,{recursive:true,force:true}); }
}
function saveAtomic(file, source) {
  fs.mkdirSync(path.dirname(file),{recursive:true});
  const temp=path.join(path.dirname(file),`.goofy-${process.pid}-${Date.now()}-${Math.random().toString(16).slice(2)}.tmp`);
  try {fs.writeFileSync(temp,source,'utf8');fs.renameSync(temp,file)}
  finally {if(fs.existsSync(temp))fs.unlinkSync(temp)}
}

const lua = engine==='lune' ? null : luaCandidate();
let missing=0;
for(let i=0;i<inputs.length;i++) {
  const filename=path.resolve(inputs[i]);
  const target=batch?path.resolve(output,`depth-${i+1}`,'deobfuscated.lua'):path.resolve(output);
  if(filename===target) {
    console.error('Refusing to overwrite input: '+filename);missing++;continue;
  }
  let protectedLua;
  try {protectedLua=fs.readFileSync(filename,'utf8')}
  catch(e) {console.error('Cannot read '+filename+': '+e.message);missing++;continue}

  let result, verified=false, reason='', candidates=[];
  try {
    const info=unpack(filename);
    verified=true;
    reason=`V11 transport ${info.transport.firstLength}+${info.transport.secondLength} bytes`;
  } catch(e) {reason='transport unsupported: '+safeComment(e.message)}

  if(verified) {
    if(engine!=='lua' && fs.existsSync(luneProbe)) {
      const cap=luneRun(luneBinary,filename);
      if(isUsableLua(cap.body)) candidates.push(cap);
    }
    if(engine!=='lune' && lua) {
      const cap=luaRun(lua,filename);
      if(isUsableLua(cap.body)) candidates.push(cap);
    }
  }
  candidates.sort((a,b)=>score(b.body)-score(a.body));
  if(candidates.length) {
    const best=candidates[0];
    result = '--larpcorupt gooning club\n' +
    best.body.replace(/^\uFEFF/, '').trimEnd() + '\n';

    reason += `; ${best.engine}, score=${score(best.body)}`;
    if(best.incomplete) reason+='; probe incomplete';
  } else {
    // Never pretend VM wrapper preservation is recovery; it is explicitly labelled.
    result='-- RECOVERY STATUS: INCOMPLETE; NO LUA SOURCE INFERRED\n'+
      '-- Original protected script retained so this output remains executable.\n'+
      '-- '+safeComment(reason)+'\n'+protectedLua;
    if(!result.endsWith('\n'))result+='\n';
    reason+='; original protected script retained';
  }

  // A syntax check is advisory only: a Luau trace may not be understood by Lua 5.4.
  if(lua) {
    const temp=path.join(os.tmpdir(),`goofy-check-${process.pid}-${i}.lua`);
    try {
      fs.writeFileSync(temp,result,'utf8');
      const check=runtime(lua,[checker,temp],7000);
      if(check.status!==0) reason+='; Lua syntax check unavailable/failed';
    } finally {fs.rmSync(temp,{force:true})}
  }
  try {
    saveAtomic(target,result);
    console.log(`${path.basename(filename)} -> ${target}`);
    console.log('  '+reason);
    console.log(candidates.length?'  PARTIAL TRACE: NOT COMPLETE VM DEOBFUSCATION':'  INCOMPLETE: PROTECTED SOURCE RETAINED');
  } catch(e) {
    console.error('Failed to write '+target+': '+e.message);missing++;
  }
}
// Discord bots can treat a written .lua file as a successful file operation;
// the explicit status comment says how much was actually recovered.
process.exitCode=missing?1:0;
