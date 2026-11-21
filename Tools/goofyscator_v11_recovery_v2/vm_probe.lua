-- Optional offline VM structure probe for Lua 5.3/5.4 or LuaTeX's texlua.
-- Loads the wrapper's function table, instruments the proto builder, and aborts
-- before the protected virtual machine begins executing user instructions.
local infile, builder, instructionKey, maxRecords, outfile = arg[1], arg[2], tonumber(arg[3]), tonumber(arg[4]) or 2000, arg[5]
local f=assert(io.open(infile,'rb')); local src=f:read('*a');f:close()
local p,suffix=src:gsub('%}%):[%a_][%w_]*%(getfenv and getfenv%(%) or _ENV or _G%);?%s*$', '})')
if suffix~=1 then error('Unrecognized V11 wrapper entry form',0) end
local entry=src:match('%}%):([%a_][%w_]*)%(getfenv and getfenv%(%) or _ENV or _G%);?%s*$')
local safe={}
for _,name in ipairs({'assert','error','getmetatable','ipairs','next','pairs','pcall','rawequal','rawget','rawset','select','setmetatable','tonumber','tostring','type','xpcall'}) do safe[name]=_G[name] end
-- Lua 5.4 removed the optional bit32 library. The protected Goofyscator VM
-- still references it, so expose 32-bit bitwise operations inside the harness.
-- No external rocks, dlls, PATH edits, or host globals are needed.
local function makeBit32()
  local MASK = 0xFFFFFFFF
  local function u32(x)
    assert(type(x) == "number", "bit32: number expected")
    return math.floor(x % 4294967296) & MASK
  end
  local b = {}
  function b.band(...)
    local x = MASK
    for i = 1, select('#', ...) do x = x & u32(select(i, ...)) end
    return x & MASK
  end
  function b.bor(...)
    local x = 0
    for i = 1, select('#', ...) do x = x | u32(select(i, ...)) end
    return x & MASK
  end
  function b.bxor(...)
    local x = 0
    for i = 1, select('#', ...) do x = x ~ u32(select(i, ...)) end
    return x & MASK
  end
  function b.bnot(x) return (~u32(x)) & MASK end
  local lshift, rshift
  lshift = function(x, d)
    d = math.floor(d)
    if d < 0 then return rshift(x, -d) end
    if d >= 32 then return 0 end
    return (u32(x) << d) & MASK
  end
  rshift = function(x, d)
    d = math.floor(d)
    if d < 0 then return lshift(x, -d) end
    if d >= 32 then return 0 end
    return u32(x) >> d
  end
  b.lshift, b.rshift = lshift, rshift
  function b.arshift(x, d)
    d = math.floor(d)
    if d < 0 then return lshift(x, -d) end
    local v = u32(x)
    if d >= 32 then return (v & 0x80000000) ~= 0 and MASK or 0 end
    if (v & 0x80000000) ~= 0 then v = v | (~MASK) end
    return (v >> d) & MASK
  end
  function b.lrotate(x, d)
    local n = math.floor(d) % 32
    local v = u32(x)
    if n == 0 then return v end
    return ((v << n) | (v >> (32 - n))) & MASK
  end
  function b.rrotate(x, d) return b.lrotate(x, -d) end
  function b.btest(...) return b.band(...) ~= 0 end
  local function fieldcheck(f, w)
    f = math.floor(f)
    w = math.floor(w or 1)
    assert(f >= 0 and w >= 1 and f + w <= 32, 'bit32: invalid field')
    return f, w
  end
  function b.extract(x, f, w)
    f, w = fieldcheck(f, w)
    return (u32(x) >> f) & ((1 << w) - 1)
  end
  function b.replace(x, v, f, w)
    f, w = fieldcheck(f, w)
    local mask = ((1 << w) - 1) << f
    return ((u32(x) & (~mask)) | (u32(v) << f & mask)) & MASK
  end
  return b
end
local bit32compat = bit32 or makeBit32()
safe.string=string; safe.math=math; safe.table=table; safe.bit32=bit32compat
safe.coroutine=coroutine; safe.unpack=table.unpack
safe._G=safe;safe._ENV=safe
local chunk,err=load(p,'=inspected_wrapper','t',safe)
if not chunk then error(err,0)end
local tab=chunk()
if type(tab[builder])~='function' then error('Prototype builder function missing: '..tostring(builder),0)end
local aliases={}
for k,v in pairs(tab)do if type(v)=='function' then aliases[v]=aliases[v] or tostring(k) end end
local function esc(s)
  return (s:gsub('[%z\1-\31\\"]',function(c)
    if c=='"'then return '\\"'elseif c=='\\' then return '\\\\'end
    return string.format('\\u%04x',string.byte(c))
  end))
end
local function encode(v,depth,seen)
  local tv=type(v)
  if tv=='nil' then return 'null'
  elseif tv=='boolean' then return tostring(v)
  elseif tv=='number' then if v~=v or v==math.huge or v==-math.huge then return 'null' end; return tostring(v)
  elseif tv=='string' then
    if #v>256 then return '{"length":'..#v..',"previewHex":"'..(v:sub(1,64):gsub('.',function(c)return string.format('%02x',string.byte(c))end))..'"}'end
    if v:find('[^%g%s]') then return '{"length":'..#v..',"hex":"'..(v:gsub('.',function(c)return string.format('%02x',string.byte(c))end))..'"}'end
    return '"'..esc(v)..'"'
  elseif tv=='function' then return '"<handler:'..esc(aliases[v] or 'dynamic')..'>"'
  elseif tv~='table' then return '"<'..tv..'>"' end
  if depth>=6 then return '"<max-depth>"' end
  if seen[v] then return '"<cycle>"' end
  seen[v]=true
  local n=0;local a={}
  for k,x in pairs(v)do
    n=n+1;if n>48 then a[#a+1]='"__truncated":true';break end
    a[#a+1]='"'..esc(tostring(k))..'":'..encode(x,depth+1,seen)
  end
  seen[v]=nil
  table.sort(a)
  return '{'..table.concat(a,',')..'}'
end
local found={}
local original=tab[builder]
local sentinel={}
tab[builder]=function(...)
  local proto=original(...)
  if type(proto)=='table' then
    local ins=proto[instructionKey]; local rows={}
    if type(ins)=='table' then
      for pc=1,maxRecords do
        local ok,op=pcall(function()return ins[pc] end)
        if not ok then rows[#rows+1]='{"pc":'..pc..',"error":"'..esc(tostring(op))..'"}';break end
        if op==nil then break end
        local fn=nil
        if type(op)=='table' then for _,candidate in pairs(op) do if type(candidate)=='function' then fn=candidate;break end end end
        local nam=type(fn)=='function' and (aliases[fn] or 'dynamic') or 'unresolved'
        rows[#rows+1]='{"pc":'..pc..',"handler":"'..esc(nam)..'","raw":'..encode(op,0,{})..'}'
      end
    end
    local meta={}
    for k,v in pairs(proto)do if type(k)=='number' and k~=instructionKey then meta[#meta+1]='"'..k..'":'..encode(v,0,{}) end end
    found[#found+1]='{"records":['..table.concat(rows,',')..'],"meta":{'..table.concat(meta,',')..'}}'
  end
  error(sentinel,0) -- Never permit the protected program to execute.
end
local ok,result=pcall(tab[entry],tab,safe)
local status=not ok and result==sentinel and 'captured' or (ok and 'entry-returned' or 'runtime-error')
local s='{"status":"'..status..'","builder":"'..esc(builder)..'","entry":"'..esc(entry)..'","prototypes":['..table.concat(found,',')..']}'
local f2=assert(io.open(outfile,'wb')); f2:write(s);f2:close()
if status~='captured' then io.stderr:write('VM probe did not reach prototype: ',tostring(result),'\n') end
