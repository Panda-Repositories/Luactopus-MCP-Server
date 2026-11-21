-- Dynamic observation module for Goofyscator V11.
-- This captures print/warn calls in a deliberately restricted environment.
-- It is NOT a bytecode devirtualizer and does NOT prove that hidden branches
-- or other side effects have been reconstructed.
local input = assert(arg[1], 'missing input')
local file = assert(io.open(input, 'rb'))
local script = file:read('*a')
file:close()
local withoutCall, replaced = script:gsub('%}%):[%a_][%w_]*%(getfenv and getfenv%(%) or _ENV or _G%);?%s*$', '})')
assert(replaced == 1, 'unknown V11 entry pattern')
local entry = assert(script:match('%}%):([%a_][%w_]*)%(getfenv and getfenv%(%) or _ENV or _G%);?%s*$'))

local effects, violations, reads, pendingCallbacks = {}, {}, {}, {}
local function literal(v)
  local kind = type(v)
  if kind == 'table' and type(rawget(v, '__expr')) == 'string' then return rawget(v, '__expr') end
  if kind == 'string' then
    local a = {'"'}
    for i = 1, #v do
      local c = string.byte(v, i)
      if c == 34 then a[#a+1] = '\\"'
      elseif c == 92 then a[#a+1] = '\\\\'
      elseif c < 32 or c > 126 then a[#a+1] = string.format('\\%03d', c)
      else a[#a+1] = string.char(c) end
    end
    a[#a+1] = '"'
    return table.concat(a)
  elseif kind == 'boolean' or kind == 'nil' then
    return tostring(v)
  elseif kind == 'number' then
    if v ~= v or v == math.huge or v == -math.huge then return nil end
    return string.format('%.17g', v)
  end
  return nil
end
local function record(fn, ...)
  local a, n = {}, select('#', ...)
  for i = 1, n do
    local value = literal(select(i, ...))
    if not value then
      violations[#violations+1] = 'unsupported '..fn..' argument # '..i
      return
    end
    a[#a+1] = value
  end
  effects[#effects+1] = fn..'('..table.concat(a, ', ')..')'
end

local safe = {}
for _,k in ipairs({'assert', 'error', 'getmetatable', 'ipairs', 'next', 'pairs', 'pcall', 'rawequal', 'rawget', 'rawset', 'select', 'setmetatable', 'tonumber', 'tostring', 'type', 'xpcall'}) do safe[k] = _G[k] end
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
safe.math = math; safe.table = table; safe.string = string; safe.bit32 = bit32compat
safe.coroutine = setmetatable({yield = function(...) return ... end}, {__index = coroutine})
safe.unpack = table.unpack or unpack
safe.print = function(...) record('print', ...) end
safe.warn = function(...) record('warn', ...) end
safe._G = safe; safe._ENV = safe
safe.getfenv = function() return safe end
safe.setfenv = function(f) return f end
safe.load = function(src, name)
  if type(src) ~= 'string' then return nil, 'source must be a string' end
  return load(src, name or '=dynamic', 't', safe)
end
safe.loadstring = safe.load
safe.debug = {getinfo = debug.getinfo, info=debug.getinfo, getupvalue=debug.getupvalue, getlocal=debug.getlocal, traceback=debug.traceback}
safe.Random = {new = function(seed) return {NextInteger=function(_,a,b)return a end, NextNumber=function(_,a,b)return a or 0 end} end}
-- Lightweight Roblox host-effect recorder, used only if the VM reaches GUI code.
local objectCount=0
local function hostExpr(e) return { __expr=e } end
local function constructor(name)
  return function(...)
    local args={}
    for i=1,select('#',...) do
      local part=literal(select(i,...))
      if not part then return nil end
      args[#args+1]=part
    end
    return hostExpr(name..'('..table.concat(args,', ')..')')
  end
end
safe.UDim2={new=constructor('UDim2.new'),fromOffset=constructor('UDim2.fromOffset'),fromScale=constructor('UDim2.fromScale')}
safe.UDim={new=constructor('UDim.new')}
safe.Color3={new=constructor('Color3.new'),fromRGB=constructor('Color3.fromRGB'),fromHSV=constructor('Color3.fromHSV')}
safe.Enum={Font={GothamBold=hostExpr('Enum.Font.GothamBold')}}
safe.Instance={new=function(class,parent)
  if type(class) ~= 'string' then return nil end
  objectCount=objectCount+1
  local id='object_'..objectCount
  local parentExpr=parent and literal(parent) or nil
  local creation='local '..id..' = Instance.new('..assert(literal(class))..(parentExpr and ', '..parentExpr or '')..')'
  effects[#effects+1]=creation
  local properties={__expr=id}
  return setmetatable({}, {
    __index=function(_,key)
      if key=='MouseButton1Click' or key=='Activated' or key=='MouseButton2Click' then
        return {Connect=function(_,fn)
          if type(fn)~='function' then return nil end
          local slot=#effects+1
          effects[slot]='-- callback pending: '..id..'.'..key
          pendingCallbacks[#pendingCallbacks+1]={fn=fn,slot=slot,event=id..'.'..key}
          return {}
        end}
      end
      return properties[key]
    end,
    __newindex=function(_,key,value)
      local expr=literal(value)
      if expr then effects[#effects+1]=id..'.'..tostring(key)..' = '..expr
      else violations[#violations+1]='unrepresentable property '..tostring(key) end
      properties[key]=value
    end
  })
end}

local none = {}
setmetatable(none, {
  __index=function(self,key)
    if key == 'Inverse' or key == 'ToWorldSpace' or key == 'ToObjectSpace' or key == 'Lerp' then
      return function() return self end
    end
    return self
  end,
  __call = function() return none end,
  __add = function() return none end,
  __sub = function() return none end,
  __mul = function() return none end,
  __div = function() return none end,
})
safe.CFrame = {new=function()return none end, Angles=function()return none end}
safe.Vector3 = {new=function()return none end}
safe.workspace = {DistributedGameTime=100, CurrentCamera={CFrame=none}, GetServerTimeNow=function()return 100 end}
safe.game = {PlaceId=1, JobId='', GameId=1, StarterGui=hostExpr('game.StarterGui'), CoreGui=hostExpr('game.CoreGui'), GetService=function(_,name)
  if name == 'Workspace' then return safe.workspace end
  if name == 'StarterGui' then return safe.game.StarterGui end
  if name ~= 'RunService' and name ~= 'Players' and name ~= 'TweenService' then
    violations[#violations+1] = 'mock service: '..tostring(name)
  end
  return {}
end}
safe.task = {wait=function()return 0 end,spawn=function(f) f() end,defer=function(f) f() end,delay=function(_,f) f() end}
setmetatable(safe, {__index = function(_, key)
  reads[#reads+1] = tostring(key)
  return nil
end})
local wrapper, loadErr = load(withoutCall, '=v11_wrapper', 't', safe)
if not wrapper then error(loadErr,0) end
local fnTable = wrapper()
if type(fnTable) ~= 'table' or type(fnTable[entry]) ~= 'function' then error('V11 entry not found',0) end
local hookCount = 0
local function limitHook()
  hookCount = hookCount + 1
  if hookCount > 100000 then error('instruction budget exceeded', 0) end
end
-- Limit total Lua VM instructions, not only the target's print output.
debug.sethook(limitHook, '', 1000)
local ok, result = pcall(fnTable[entry], fnTable, safe)
debug.sethook()
-- Probe registered callbacks once in a mocked environment. This is only an
-- observation of a single path, not proof of callback/source equivalence.
if ok then
  for _,cb in ipairs(pendingCallbacks) do
    local outer=effects
    effects={}
    local cbOk, cbError=pcall(cb.fn)
    local cbEffects=effects
    effects=outer
    if cbOk then
      local lines={}
      for _,line in ipairs(cbEffects) do lines[#lines+1]='    '..line end
      effects[cb.slot]=cb.event..':Connect(function()\n'..table.concat(lines,'\n')..'\nend)'
    else
      effects[cb.slot]='-- callback not executed: '..tostring(cbError):gsub('[\r\n]+',' ')
    end
  end
end
local notices = {}
if not ok then notices[#notices+1] = 'runtime: '..tostring(result) end
if #violations > 0 then notices[#notices+1] = 'unsupported host calls: '..#violations end
if #reads > 0 then notices[#notices+1] = 'unknown globals: '..#reads end
if #effects == 0 then notices[#notices+1] = 'no observed print/warn calls' end
if ok and result ~= nil then
  local value = literal(result)
  if value then effects[#effects+1] = 'return '..value
  else notices[#notices+1] = 'return value could not be represented' end
end
-- Always emit the observations, including when the protected program throws.
-- The Node CLI decides whether to retain this trace or the protected source.
for _,x in ipairs(effects) do io.write(x, '\n') end
io.stderr:write('observed_calls=', tostring(#effects),
 ' hook_samples=', tostring(hookCount),
 ' probe=', #notices == 0 and 'completed' or 'incomplete', '\n')
for _,msg in ipairs(notices) do io.stderr:write('trace-warning: ', msg, '\n') end
