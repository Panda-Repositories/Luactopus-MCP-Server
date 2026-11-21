from config import IB1_CMD
from .cli_runner import run_cli_backend
async def run_ib1(source): return await run_cli_backend(source, IB1_CMD, name='IronBrew 1')
