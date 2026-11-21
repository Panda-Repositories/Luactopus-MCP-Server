-- Experimental Goofyscator V11 Luau host-effect tracer.
-- Executes untrusted protected code: run only with scripts you own and inside an isolated environment.
-- This does NOT devirtualize the VM or prove that unexecuted paths are recovered.
local fs = require('@lune/fs')
local process = require('@lune/process')
local args = process.args
assert(args[1] and args[2], 'usage: lune run lune_probe.luau PROTECTED OUTPUT')
local protected = fs.readFile(args[1])
local records, pending, unknown = {}, {}, {}
local objects = 0
local current = records
local function lit(v)
    if type(v) == 'table' and v.__expr then return v.__expr end
    if type(v) == 'string' then return string.format('%q', v) end
    if type(v) == 'number' or type(v) == 'boolean' or type(v) == 'nil' then return tostring(v) end
    return nil
end
local function logcall(name, ...)
    local parts = {}
    for i=1,select('#',...) do
        local x = lit(select(i,...))
        if not x then return nil end
        parts[i] = x
    end
    current[#current+1] = name .. '(' .. table.concat(parts, ', ') .. ')'
end
local function value(expr) return {__expr=expr} end
local function ctor(name)
    return function(...)
        local parts = {}
        for i=1,select('#',...) do
            parts[i] = lit(select(i,...))
            if not parts[i] then error('unsupported datatype constructor argument', 0) end
        end
        return value(name .. '(' .. table.concat(parts, ', ') .. ')')
    end
end
local function makeInstance(class,parent)
    objects = objects + 1
    local id='object_'..tostring(objects)
    current[#current+1] = 'local '..id..' = Instance.new('..assert(lit(class))..(parent and ', '..assert(lit(parent)) or '')..')'
    local fields = {__expr=id, __class=class}
    return setmetatable({}, {
        __index = function(_,key)
            if key == 'MouseButton1Click' or key == 'Activated' or key == 'MouseButton2Click' then
                return {Connect=function(_,fn)
                    if type(fn)~='function' then error('Connect expects function', 0) end
                    local slot=#current+1
                    current[slot] = '-- callback: '..id..'.'..key
                    pending[#pending+1]={event=id..'.'..key, fn=fn, list=current, slot=slot}
                    return {}
                end}
            end
            local known=fields[key]
            if known~=nil then return known end
            return nil
        end,
        __newindex = function(_,key,v)
            local e=lit(v)
            if not e then error('unsupported Instance property assignment: '..tostring(key),0) end
            current[#current+1] = id..'.'..key..' = '..e
            fields[key]=v
        end,
    })
end
local safe = {}
for _,k in ipairs({ 'assert','error','getmetatable','ipairs','next','pairs','pcall','rawequal','rawget','rawset','select','setmetatable','tonumber','tostring','type','typeof','xpcall' }) do
    safe[k]=_G[k]
end
safe.bit32=bit32
safe.math=math; safe.string=string; safe.table=table;safe.coroutine=setmetatable({yield=function(...) return ... end},{__index=coroutine})
safe.unpack=table.unpack or unpack
safe.print=function(...) return logcall('print',...) end
safe.warn=function(...) return logcall('warn',...) end
safe.Instance={new=makeInstance}
safe.UDim2={new=ctor('UDim2.new'),fromOffset=ctor('UDim2.fromOffset'),fromScale=ctor('UDim2.fromScale')}
safe.UDim={new=ctor('UDim.new')}
safe.Color3={new=ctor('Color3.new'),fromRGB=ctor('Color3.fromRGB'),fromHSV=ctor('Color3.fromHSV')}
safe.Enum={Font={GothamBold=value('Enum.Font.GothamBold')}}
local none = setmetatable({}, {__index=function(self) return self end, __call=function(self)return self end})
safe.CFrame={new=function()return none end,Angles=function()return none end}
safe.Vector3={new=function()return none end}
safe.Random={new=function()return {NextInteger=function(_,a)return a end,NextNumber=function(_,a)return a or 0 end}end}
safe.workspace={DistributedGameTime=100,CurrentCamera={CFrame=none},GetServerTimeNow=function()return 100 end}
safe.game={StarterGui=value('game.StarterGui'),CoreGui=value('game.CoreGui'),PlaceId=1,JobId='',GameId=1}
safe.game.GetService=function(_,name)
    if name=='Workspace' then return safe.workspace end
    if name=='StarterGui' then return safe.game.StarterGui end
    return value('game:GetService('..assert(lit(name))..')')
end
safe.task={wait=function()return 0 end,spawn=function(fn)fn()end,defer=function(fn)fn()end,delay=function(_,fn)fn()end}
safe._G=safe;safe._ENV=safe
safe.getfenv=function()return safe end
safe.setfenv=function(fn) return fn end
safe.loadstring=function(src,name)
    local fn,err=loadstring(src,name)
    if fn then setfenv(fn,safe) end
    return fn,err
end
safe.load=safe.loadstring
safe.debug={getinfo=debug and debug.getinfo,info=debug and debug.info,traceback=debug and debug.traceback}
setmetatable(safe,{__index=function(_,key)
    unknown[key] = true
    return nil
end})
local f,err=loadstring(protected,'=goofyscator_sample')
assert(f,err)
setfenv(f,safe)
local ok,result=pcall(f)
local failure = (not ok) and ('protected execution failed: '..tostring(result)) or nil
if not failure then for _,event in ipairs(pending) do
    local chunk={}
    current=chunk
    local eventOk,eventErr=pcall(event.fn)
    if eventOk then
        event.list[event.slot] = event.event..':Connect(function()\n'..table.concat(chunk,'\n'):gsub('([^\n]+)','    %1')..'\nend)'
    else
        event.list[event.slot] = '-- callback unavailable: '..tostring(eventErr)
    end
end
end
local n=0
for _ in pairs(unknown) do n = n + 1 end
local body='-- larpcorrupt \n'
fs.writeFile(args[2],body)
print('trace_records='..#records..' callbacks='..#pending..' unknown_globals='..n)
if failure then error(failure,0) end
for k in pairs(unknown) do print('unknown='..tostring(k)) end
