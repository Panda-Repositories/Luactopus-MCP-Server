from dataclasses import dataclass
from pathlib import Path
import json, re
@dataclass
class Detection:
    kind:str; name:str; confidence:float; supported:bool=True; reason:str=""
FP=Path(__file__).parent/"fingerprints"/"terrorlua.json"
def features(src):
    s=src.lower(); f=set()
    lits=["--ironbrew3","ironbrew3","ironbrew","aztupbrew","luaobfuscator","luraph","lph_","moonsec","moonveil","prometheus","getfenv","setfenv","loadstring","string.char","string.byte","bit32","bit.bxor","coroutine.wrap","coroutine.create","table.concat","math.floor","return(function","while true do"]
    for x in lits:
        if x in s: f.add("lit:"+x)
    if re.search(r'["\'][0-9a-f]{512,}["\']',src,re.I): f.add("shape:large_hex_string")
    if len(re.findall(r"\bfunction\b",src))>50: f.add("shape:many_functions")
    if len(re.findall(r"\bwhile\b|\brepeat\b",src))>20: f.add("shape:many_loops")
    if len(re.findall(r"\bbit32\b|\bbit\.",src))>5: f.add("shape:bit_heavy")
    if len(re.findall(r"\[[^\]]+\]\s*=",src))>50: f.add("shape:table_dispatch")
    if "return(function" in s and "string.byte" in s and "math.floor" in s: f.add("shape:lua_vm_wrapper")
    return f
def jacc(a,b): return len(a&b)/len(a|b) if a and b else 0
def map_folder(n):
    l=n.lower()
    if "ironbrew3" in l or l=="ib3": return "ib3","IronBrew 3",True
    if "ironbrew2" in l or "aztup" in l or l=="ib2": return "ib2","IronBrew 2 / AztupBrew",True
    if "ironbrew1" in l or l=="ib1": return "ib1","IronBrew 1",True
    if "luaobfuscator" in l: return "luaobfuscator","LuaObfuscator",True
    if "luraph" in l: return "unsupported","Luraph",False
    if "moonsec" in l: return "unsupported","MoonSec",False
    if "moonveil" in l: return "unsupported","MoonVeil",False
    if "prometheus" in l: return "unsupported","Prometheus",False
    return "unknown",n,False
def detect_obfuscator(src):
    s=src.lower(); f=features(src)
    if "--ironbrew3" in s or "ironbrew3" in s: return Detection("ib3","IronBrew 3",.99,True,"direct")
    if "aztupbrew" in s: return Detection("ib2","AztupBrew",.99,True,"direct")
    if "luaobfuscator" in s: return Detection("luaobfuscator","LuaObfuscator",.99,True,"direct")
    if "luraph" in s or "lph_" in s: return Detection("unsupported","Luraph",.95,False,"direct")
    db={}
    if FP.exists():
        try: db=json.loads(FP.read_text(encoding="utf-8"))
        except Exception: db={}
    best=(0,None)
    for folder,item in db.items():
        sc=jacc(f,set(item.get("features",[])))
        if sc>best[0]: best=(sc,folder)
    if best[1] and best[0]>=.18:
        k,n,sup=map_folder(best[1])
        if k!="unknown": return Detection(k,n,min(.94,max(.50,best[0])),sup,"terrorlua:"+best[1])
    if "ironbrew" in s: return Detection("ib2","IronBrew-style VM",.65,True,"weak")
    if {"shape:large_hex_string","shape:lua_vm_wrapper"} <= f: return Detection("ib3","IronBrew 3 candidate",.55,True,"shape")
    raise ValueError("Couldn't confidently identify this obfuscator.")
