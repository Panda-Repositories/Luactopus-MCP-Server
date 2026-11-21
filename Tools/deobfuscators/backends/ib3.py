import asyncio
def _local(source):
    try:
        from deobfuscator import parse_ib3, find_root
    except Exception as e: raise RuntimeError(f"Local IB3 parser missing: {e}")
    p=parse_ib3(source); root=find_root(p.prototypes)
    lines=[f"-- IB3 decoded program",f"-- profile: {p.profile}",f"-- constants: {len(p.constants)}",f"-- prototypes: {len(p.prototypes)}",f"-- root candidate: {root}","","-- Unknown randomized opcode semantics are emitted as IR comments.",""]
    for i,fn in enumerate(p.prototypes):
        lines += [f"-- prototype {i} params={fn.params}",f"local function fn_{i}(...)"]
        for pc,x in enumerate(fn.instructions,1):
            lines.append(f"    -- [{pc}] opcode={x.opcode} jump={x.jump} extra={x.extra!r} b={x.b} a={x.a} c={x.c}")
        lines += ["end",""]
    lines.append(f"return fn_{root}(...)")
    return "\n".join(lines)
async def run_ib3(source): return await asyncio.to_thread(_local, source)
