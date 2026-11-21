'use strict';
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const cp=require('node:child_process');
const assert=require('node:assert/strict');
const work=fs.mkdtempSync(path.join(os.tmpdir(),'goofy-v11-test-'));
try {
  const targets=[...Array(5)].map((_,i)=>`depth-${i+1}.lua`).concat('gui-depth3.lua');
  for(const target of targets) {
    const dest=path.join(work,target.replace('.lua',''),'deobfuscated.lua');
    const res=cp.spawnSync(process.execPath,[path.join(__dirname,'deobf.js'),path.join(__dirname,'samples',target),'-o',dest,'--engine','lua'],{encoding:'utf8',timeout:40000});
    assert.equal(res.status,0,(res.stderr||'')+(res.stdout||''));
    assert.ok(fs.existsSync(dest),`Missing output for ${target}`);
    const code=fs.readFileSync(dest,'utf8');
    assert.ok(/RECOVERY STATUS: (?:PARTIAL DYNAMIC TRACE|INCOMPLETE)/.test(code),target+' missing status');
    if(target==='gui-depth3.lua'&&code.includes('PARTIAL DYNAMIC TRACE')) assert.ok(code.includes('print("Hello World")'));
    console.log('PASS output file for '+target);
  }
  const src=path.join(__dirname,'samples','gui-depth3.lua');
  const dest=path.join(work,'fallback','deobfuscated.lua');
  const fallback=cp.spawnSync(process.execPath,[path.join(__dirname,'deobf.js'),src,'-o',dest,'--engine','lua','--lua','missing_lua_binary'],{encoding:'utf8',timeout:40000});
  assert.equal(fallback.status,0);
  assert.ok(fs.readFileSync(dest,'utf8').includes('INCOMPLETE; NO LUA SOURCE INFERRED'));
  assert.ok(fs.readFileSync(dest,'utf8').includes('protected by goofyscator V11'));
  console.log('PASS incomplete fallback retains protected script');
} finally {fs.rmSync(work,{recursive:true,force:true})}
