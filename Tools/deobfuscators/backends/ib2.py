from config import IB2_CMD
from .cli_runner import run_cli_backend
async def run_ib2(source): return await run_cli_backend(source, IB2_CMD, name='IronBrew 2 / AztupBrew')
