'use strict';
const assert=require('node:assert/strict');
const path=require('node:path');
const fs=require('node:fs');
const os=require('node:os');
const {unpack,save}=require('./decode');
const {detectProtoBuilder,lift}=require('./vm');
const expected=[
 {sizes:[29279,19039],builder:'ZDT',records:297},
 {sizes:[29709,18668],builder:'HF',records:294},
 {sizes:[28980,19432],builder:'yc',records:297},
 {sizes:[29276,17389],builder:'G',records:295},
 {sizes:[29566,19769],builder:'Zt',records:295},
];
const tmp=fs.mkdtempSync(path.join(os.tmpdir(),'v11-test-'));
try{
 for(let i=1;i<=5;i++){
  const file=path.join(__dirname,'samples',`depth-${i}.lua`);
  const {src,transport}=unpack(file);
  assert.deepEqual([transport.firstLength,transport.secondLength],expected[i-1].sizes);
  assert.equal(transport.first.length,transport.firstLength);
  assert.equal(transport.second.length,transport.secondLength);
  const info=detectProtoBuilder(src);
  assert.equal(info.name,expected[i-1].builder);
  const out=path.join(tmp,`depth-${i}`);
  save(file,out);
  assert.equal(fs.readFileSync(path.join(out,'segment-1.bin')).length,expected[i-1].sizes[0]);
  if(process.env.GOOFY_TEST_LUA){
    const probe=lift(file,out,{lua:process.env.GOOFY_TEST_LUA,max:1000});
    assert.equal(probe.instructions,expected[i-1].records);
  }
  console.log(`PASS depth ${i}: header, segmentation, prototype-discovery${process.env.GOOFY_TEST_LUA?', VM IR':''}`);
 }
}finally{fs.rmSync(tmp,{recursive:true,force:true});}
