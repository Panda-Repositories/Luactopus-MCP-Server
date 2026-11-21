from .detector import detect_obfuscator, Detection
from .errors import DeobfuscationError
from .backends.ib1 import run_ib1
from .backends.ib2 import run_ib2
from .backends.ib3 import run_ib3
from .backends.luaobfuscator import run_luaobfuscator
async def deobfuscate_script(kind, source):
    if kind=="auto":
        det=detect_obfuscator(source); kind=det.kind
        if not det.supported: raise DeobfuscationError(f"Detected {det.name}, but automatic deobfuscation for it is not supported yet.")
    else:
        det=Detection(kind,{"ib1":"IronBrew 1","ib2":"IronBrew 2 / AztupBrew","ib3":"IronBrew 3","luaobfuscator":"LuaObfuscator"}.get(kind,kind),1.0,True,"manual")
    if kind=="ib1": return await run_ib1(source),det
    if kind=="ib2": return await run_ib2(source),det
    if kind=="ib3": return await run_ib3(source),det
    if kind=="luaobfuscator": return await run_luaobfuscator(source),det
    raise DeobfuscationError(f"Unsupported backend: {kind}")
