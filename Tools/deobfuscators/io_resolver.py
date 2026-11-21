import re, aiohttp, discord
from config import MAX_INPUT_BYTES
EXT=(".lua",".luau",".txt",".md")
MDURL=re.compile(r'^\[(https?://[^\]]+)\]\((https?://[^)\s]+)(?:\s+"[^"]*")?\)$',re.I)
URL=re.compile(r'^https?://[^\s<>]+$',re.I)
CB=re.compile(r'^```(?:lua|luau|txt)?\s*\n?(.*?)\n?```$',re.I|re.S)
def strip_codeblock(s):
    m=CB.match(s.strip()); return m.group(1).strip() if m else s.strip()
def extract_url(s):
    s=s.strip(); m=MDURL.match(s)
    if m: return m.group(2)
    m=URL.match(s); return m.group(0) if m else None
async def download_attachment(a):
    if not a.filename.lower().endswith(EXT): raise ValueError("File must be .lua, .luau, .txt, or .md")
    if a.size>MAX_INPUT_BYTES: raise ValueError("File is too large")
    b=await a.read()
    if len(b)>MAX_INPUT_BYTES: raise ValueError("File is too large")
    return b.decode("utf-8","replace")
async def download_url(url):
    timeout=aiohttp.ClientTimeout(total=25)
    async with aiohttp.ClientSession(timeout=timeout) as s:
        async with s.get(url,allow_redirects=True) as r:
            if r.status!=200: raise ValueError(f"URL returned HTTP {r.status}")
            b=await r.content.read(MAX_INPUT_BYTES+1)
            if len(b)>MAX_INPUT_BYTES: raise ValueError("Downloaded file too large")
            return b.decode("utf-8","replace")
async def replied(ctx):
    ref=ctx.message.reference
    if not ref: return None
    if isinstance(ref.resolved, discord.Message): return ref.resolved
    if not ref.message_id: return None
    try: return await ctx.channel.fetch_message(ref.message_id)
    except discord.HTTPException: return None
async def resolve_input(ctx, source=None):
    if ctx.message.attachments: return await download_attachment(ctx.message.attachments[0])
    m=await replied(ctx)
    if m:
        if m.attachments: return await download_attachment(m.attachments[0])
        if m.content.strip(): source=m.content
    if source:
        url=extract_url(source)
        return await download_url(url) if url else strip_codeblock(source)
    raise ValueError("Give URL, file, reply, codeblock, or raw Lua.")
