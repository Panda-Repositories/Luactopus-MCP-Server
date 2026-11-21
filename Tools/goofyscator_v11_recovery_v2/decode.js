'use strict';
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

function parseNumber(s) { return Number(s); }
function luaStrings(src) {
  const ret = [];
  for (let i=0; i < src.length; i++) {
    if (src[i] !== '"' && src[i] !== "'") continue;
    const quote=src[i], start=i;
    let raw='', valid=false;
    for (i=i+1; i<src.length; i++) {
      const ch=src[i];
      if (ch===quote) { valid=true; break; }
      if (ch==='\\') {
        const n=src[++i];
        if (n===undefined) break;
        if (n==='z') { while (/\s/.test(src[i+1] || '')) i++; continue; }
        if (n==='x' && /^[a-fA-F0-9]{2}$/.test(src.slice(i+1,i+3))) {raw+=String.fromCharCode(parseInt(src.slice(i+1,i+3),16));i+=2;continue;}
        if (/[0-9]/.test(n)) { const m=src.slice(i).match(/^\d{1,3}/); raw+=String.fromCharCode(Number(m[0])%256);i+=m[0].length-1; continue; }
        const escape={a:'\x07',b:'\b',f:'\f',n:'\n',r:'\r',t:'\t',v:'\v','\\':'\\','"':'"',"'":"'",'\n':'\n'};
        raw += Object.hasOwn(escape,n) ? escape[n] : n;
      } else raw+=ch;
    }
    if (valid) ret.push({start, end:i+1, value:raw});
    if(!valid)break;
  }
  return ret;
}
function parseProfile(src) {
  const anchor = /if\s*#\w+\s*<\s*18\s*then\s*return;end;/.exec(src);
  if(!anchor) throw Error('V11 split-header initializer not found');
  const start=anchor.index;
  const sub=src.slice(start,start+3400);
  const tuple=/local\s+((?:\w+,){5}\w+)\s*=\s*((?:0x[\da-fA-F]+|\d+)(?:,(?:0x[\da-fA-F]+|\d+)){5});local function (\w+)\(/.exec(sub);
  if (!tuple) throw Error('Six-parameter randomized header profile not recognized');
  const names=tuple[1].split(','), values=tuple[2].split(',').map(parseNumber);
  const vars=Object.fromEntries(names.map((name,i)=>[name,values[i]]));
  const post=sub.slice(tuple.index+tuple[0].length);
  const wordReader=/local function (\w+)\((\w+)\)/.exec(post);
  if (!wordReader) throw Error('Word reader not found');
  const wr=post.slice(wordReader.index+wordReader[0].length);
  // Collect the same arithmetic expression used inside all five V11 variants.
  const maskRE=/\((\w+)\s*\+\s*(\w+)\s*\+\s*\(\w+\s*\*\s*(\w+)\)\s*\+\s*\(\w+\s*\*\s*(\w+)\)\)\s*%\s*256/g;
  let mask;
  while ((mask=maskRE.exec(wr))!==null) {
    if ([mask[1],mask[3],mask[4]].every(n=>Object.hasOwn(vars,n))) break;
  }
  if (!mask) throw Error('Randomized header XOR mask not recognized');
  const checkpoint=/if\s+\w+\s*~=\s*\w+\(\s*(0x[\da-fA-F]+|\d+)\s*,\s*\(\w+\s*\+\s*\w+\s*\+\s*(\w+)\)\s*%\s*256\s*\)/.exec(wr);
  if(!checkpoint)throw Error('Header checksum not recognized');
  const seedName=checkpoint[2];
  const stateName=mask[2];
  const assignment=new RegExp(`${stateName}\\s*=\\s*\\(\\s*${stateName}\\s*\\+\\s*\\w+\\s*\\+\\s*(\\w+)\\s*\\+\\s*\\(\\w+\\s*\\*\\s*\\w+\\)\\s*\\)\\s*%\\s*256`).exec(wr);
  if(!assignment) throw Error('Header state transition not recognized');
  const update=assignment[1];
  if(![mask[1],mask[3],mask[4],seedName,update].every(n=>Object.hasOwn(vars,n))) throw Error('Unresolved numeric header parameters');
  const initSeedRE=new RegExp(`\\(\\s*${seedName}\\s*\\+\\s*\\(\\w+\\s*\\*\\s*${mask[4]}\\)\\s*\\)\\s*%\\s*256`);
  if(!initSeedRE.test(wr)) throw Error('Inconsistent header seed formula');
  const readerStart=post.slice(0,wordReader.index);
  const cursors=names.filter(n=>vars[n]===1 && new RegExp(`\\b${n}\\s*=\\s*${n}\\s*\\+\\s*2`).test(readerStart));
  if(cursors.length!==1)throw Error('Header pair cursor not recognized');
  return {cursor:cursors[0],seed:vars[seedName],offset:vars[mask[1]],step:vars[mask[4]],round:vars[mask[3]],update:vars[update],checksum:Number(checkpoint[1]),profile:vars};
}
function readHeader(blob,p) {
 let offset=0;
 function byte() {
   if(offset+2>blob.length) throw Error('Transport header is incomplete');
   const a=blob.charCodeAt(offset++)-65,b=blob.charCodeAt(offset++)-80;
   if(a<0||a>15||b<0||b>15) throw Error('Transport header uses unexpected byte alphabet');
   return a*16+b;
 }
 const tag=byte();
 function word(which) {
   let state=(p.seed+which*p.step)%256;
   let result=0;
   for(let round=1;round<=4;round++) {
     const cipher=byte();
     const key=(p.offset+state+round*p.round+which*p.step)%256;
     const dec=(cipher^key)&255;
     result+=dec*2**(8*(round-1));
     state=(state+dec+p.update+round*which)%256;
   }
   return result>>>0;
 }
 const a=word(1),b=word(2);
 const expected=(p.checksum^((a+b+p.seed)%256))&255;
 if(tag!==expected)throw Error(`Header checksum mismatch: got ${tag}, expected ${expected}`);
 if(a+b+offset!==blob.length)throw Error(`Transport sizes mismatch: ${a}+${b}+${offset} != ${blob.length}`);
 if(a>64*1024*1024 || b>64*1024*1024)throw Error('Payload exceeds safety limit');
 return {tag,firstLength:a,secondLength:b,headerLength:offset,first:blob.slice(offset,offset+a),second:blob.slice(offset+a)};
}
function unpack(input) {
 const src=fs.readFileSync(input,'utf8');
 if(!/goofyscator\s+V11/i.test(src))throw Error('This decoder targets Goofyscator V11');
 const p=parseProfile(src);
 let match,unpacked;
 for(const s of luaStrings(src).sort((a,b)=>b.value.length-a.value.length).slice(0,10)) {
   try {unpacked=readHeader(s.value,p);match=s;break;}catch(e){}
 }
 if(!match)throw Error('Could not authenticate the V11 transport payload');
 return {src,profile:p,transport:unpacked,payloadRange:{start:match.start,end:match.end}};
}
function save(input,destination) {
 const {src,profile,transport,payloadRange}=unpack(input);
 fs.mkdirSync(destination,{recursive:true});
 for(const [name,data] of [['segment-1.bin',transport.first],['segment-2.bin',transport.second]])
   fs.writeFileSync(path.join(destination,name),Buffer.from(data,'latin1'));
 const report={format:'Goofyscator V11 BETA-1',input:path.basename(input),sourceBytes:Buffer.byteLength(src),payloadRange,
   verifiedHeader:true,transportLengths:[transport.firstLength,transport.secondLength],
   sha256:[transport.first,transport.second].map(s=>crypto.createHash('sha256').update(Buffer.from(s,'latin1')).digest('hex')),
   stage:'authenticated transport extraction',sourceRecovered:false,vmDevirtualized:false,
   note:'The .bin segments remain encoded VM data, not reconstructed Lua source.'};
 fs.writeFileSync(path.join(destination,'report.json'),JSON.stringify(report,null,2)+'\n');
 return report;
}
module.exports={luaStrings,parseProfile,readHeader,unpack,save};
