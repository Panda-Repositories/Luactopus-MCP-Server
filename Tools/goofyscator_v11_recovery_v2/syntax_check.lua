local version = tonumber((_VERSION or ''):match('Lua (%d+%.%d+)')) or 0
if version < 5.3 then
  io.stderr:write('Lua 5.3+ required; detected ', _VERSION or 'unknown', '\n')
  os.exit(1)
end
local f,err=loadfile(assert(arg[1])); if not f then io.stderr:write(err,'\n');os.exit(1)end;io.write('COMPILES\n')
