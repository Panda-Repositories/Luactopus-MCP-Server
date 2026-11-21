from config import LUAOBF_CMD
from .cli_runner import run_cli_backend
async def run_luaobfuscator(source): return await run_cli_backend(source, LUAOBF_CMD, name='LuaObfuscator')
