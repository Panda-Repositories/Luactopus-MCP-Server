from __future__ import annotations

import os
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env", override=False)


def _bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on", "y"}


def _int(name: str, default: int) -> int:
    raw = os.getenv(name)
    try:
        return int(raw) if raw not in (None, "") else default
    except ValueError:
        return default


def _path(name: str, default: Path) -> Path:
    raw = os.getenv(name)
    p = Path(raw).expanduser() if raw else default
    if not p.is_absolute():
        p = PROJECT_ROOT / p
    return p.resolve()


def _which(name: str, default: str) -> str:
    raw = os.getenv(name)
    if raw:
        return raw
    return shutil.which(default) or default


@dataclass
class Settings:
    server_name: str = "Luactopus"
    transport: str = "stdio"
    host: str = "127.0.0.1"
    port: int = 8765
    http_path: str = "/mcp"

    protected_mode: bool = False
    api_key: str = ""

    tools_dir: Path = PROJECT_ROOT / "Tools"
    data_dir: Path = PROJECT_ROOT / "Data"
    log_dir: Path = PROJECT_ROOT / "logs"
    workspace_dir: Path = PROJECT_ROOT / "workspace"
    storage_dir: Path = PROJECT_ROOT / "storage"
    db_path: Path = PROJECT_ROOT / "storage" / "luactopus.db"

    python_bin: str = sys.executable
    node_bin: str = "node"
    lua_bin: str = ""
    lune_bin: str = ""
    luau_dir: str = ""

    default_timeout: int = 180
    max_timeout: int = 900
    max_input_bytes: int = 8 * 1024 * 1024
    max_layers: int = 5
    allow_tool_edits: bool = True
    allow_custom_tools: bool = True
    allow_dynamic_backends: bool = True
    allow_local_paths: bool = True
    log_max_field_chars: int = 4000
    log_level: str = "INFO"

    extra: dict = field(default_factory=dict)

    @property
    def jobs_dir(self) -> Path:
        return self.workspace_dir / "jobs"

    @property
    def overrides_dir(self) -> Path:
        return self.workspace_dir / "overrides"

    @property
    def custom_tools_dir(self) -> Path:
        return self.workspace_dir / "custom_tools"

    def ensure_dirs(self) -> None:
        for d in (self.log_dir, self.workspace_dir, self.jobs_dir, self.overrides_dir,
                  self.custom_tools_dir, self.storage_dir, self.db_path.parent):
            d.mkdir(parents=True, exist_ok=True)


def load_settings() -> Settings:
    transport = (os.getenv("MCP_TRANSPORT") or "stdio").strip().lower()
    if transport in {"http", "streamable_http"}:
        transport = "streamable-http"
    s = Settings(
        server_name=os.getenv("MCP_SERVER_NAME", "Luactopus"),
        transport=transport,
        host=os.getenv("MCP_HOST", "127.0.0.1"),
        port=_int("MCP_PORT", 8765),
        http_path=os.getenv("MCP_HTTP_PATH", "/mcp"),
        protected_mode=_bool("PROTECTED_MODE", False),
        api_key=os.getenv("LUACTOPUS_API_KEY", "").strip(),
        tools_dir=_path("TOOLS_DIR", PROJECT_ROOT / "Tools"),
        data_dir=_path("DATA_DIR", PROJECT_ROOT / "Data"),
        log_dir=_path("LOG_DIR", PROJECT_ROOT / "logs"),
        workspace_dir=_path("WORKSPACE_DIR", PROJECT_ROOT / "workspace"),
        storage_dir=_path("STORAGE_DIR", PROJECT_ROOT / "storage"),
        db_path=_path("DB_PATH", PROJECT_ROOT / "storage" / "luactopus.db"),
        python_bin=os.getenv("PYTHON_BIN") or sys.executable,
        node_bin=_which("NODE_BIN", "node"),
        lua_bin=os.getenv("LUA_BIN", "") or (shutil.which("lua5.4") or shutil.which("lua") or ""),
        lune_bin=os.getenv("LUNE_BIN", "") or (shutil.which("lune") or ""),
        luau_dir=os.getenv("LUAU_DIR", ""),
        default_timeout=_int("DEFAULT_TIMEOUT", 180),
        max_timeout=_int("MAX_TIMEOUT", 900),
        max_input_bytes=_int("MAX_INPUT_BYTES", 8 * 1024 * 1024),
        max_layers=_int("MAX_LAYERS", 5),
        allow_tool_edits=_bool("ALLOW_TOOL_EDITS", True),
        allow_custom_tools=_bool("ALLOW_CUSTOM_TOOLS", True),
        allow_dynamic_backends=_bool("ALLOW_DYNAMIC_BACKENDS", True),
        allow_local_paths=_bool("ALLOW_LOCAL_PATHS", transport == "stdio"),
        log_max_field_chars=_int("LOG_MAX_FIELD_CHARS", 4000),
        log_level=os.getenv("LOG_LEVEL", "INFO").upper(),
    )
    if s.luau_dir:
        p = Path(s.luau_dir).expanduser()
        s.luau_dir = str((PROJECT_ROOT / p).resolve() if not p.is_absolute() else p)
    return s


settings = load_settings()
