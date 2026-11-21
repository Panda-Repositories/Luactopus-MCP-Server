import argparse, io, json, re, urllib.request, zipfile
from collections import defaultdict
from pathlib import Path
URL="https://github.com/terrorlua/obfuscator-samples/archive/refs/heads/main.zip"
def feats(s):
    l=s.lower(); f=set()
    for x in ["--ironbrew3","ironbrew3","ironbrew","aztupbrew","luaobfuscator","luraph","lph_","moonsec","moonveil","prometheus","getfenv","setfenv","loadstring","string.char","string.byte","bit32","bit.bxor","coroutine.wrap","coroutine.create","table.concat","math.floor","return(function","while true do"]:
        if x in l: f.add("lit:"+x)
    if re.search(r'["\'][0-9a-f]{512,}["\']',s,re.I): f.add("shape:large_hex_string")
    if len(re.findall(r"\bfunction\b",s))>50: f.add("shape:many_functions")
    if len(re.findall(r"\bwhile\b|\brepeat\b",s))>20: f.add("shape:many_loops")
    if len(re.findall(r"\bbit32\b|\bbit\.",s))>5: f.add("shape:bit_heavy")
    if len(re.findall(r"\[[^\]]+\]\s*=",s))>50: f.add("shape:table_dispatch")
    if "return(function" in l and "string.byte" in l and "math.floor" in l: f.add("shape:lua_vm_wrapper")
    return f
def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--out",type=Path,required=True); a=ap.parse_args()
    data=urllib.request.urlopen(URL,timeout=40).read()
    merged=defaultdict(set); counts=defaultdict(int)
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        for n in z.namelist():
            if not n.lower().endswith((".lua",".luau",".txt")): continue
            parts=Path(n).parts
            if len(parts)<3: continue
            folder=parts[1]; txt=z.read(n).decode("utf-8","replace")
            merged[folder].update(feats(txt)); counts[folder]+=1
    out={k:{"sample_count":counts[k],"features":sorted(v)} for k,v in sorted(merged.items())}
    a.out.parent.mkdir(parents=True,exist_ok=True); a.out.write_text(json.dumps(out,indent=2),encoding="utf-8")
    print(f"wrote {a.out} folders={len(out)}")
if __name__=="__main__": main()
