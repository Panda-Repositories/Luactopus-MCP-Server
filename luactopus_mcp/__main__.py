from __future__ import annotations

import argparse
import json
import sys


def _serve(args) -> None:
    from .config import settings
    if args.transport:
        settings.transport = "streamable-http" if args.transport in ("http", "streamable_http") else args.transport
    if args.host:
        settings.host = args.host
    if args.port:
        settings.port = args.port
    if args.protected is not None:
        settings.protected_mode = args.protected

    from . import auth, backends, storage
    from .logs import action, log, setup_logging
    setup_logging()
    storage.init_db()
    auth.bootstrap()
    installed = backends.install_luau_binaries()
    if installed:
        action("luau_installed", files=installed)
    action("server_start", transport=settings.transport, protected=settings.protected_mode,
           host=settings.host, port=settings.port)
    log.info("Luactopus starting: transport=%s protected=%s tools=%s data=%s", settings.transport,
             settings.protected_mode, settings.tools_dir, settings.data_dir)

    from .server import mcp
    if settings.transport == "stdio":
        auth.check_stdio()
        mcp.run("stdio")
        return

    import uvicorn
    from mcp.server.transport_security import TransportSecuritySettings
    import os
    allowed = [h.strip() for h in os.getenv("MCP_ALLOWED_HOSTS", "").split(",") if h.strip()]
    security = None
    if allowed:
        security = TransportSecuritySettings(enable_dns_rebinding_protection=True,
                                             allowed_hosts=allowed + [f"127.0.0.1:{settings.port}",
                                                                      f"localhost:{settings.port}"],
                                             allowed_origins=[])
    if settings.transport == "sse":
        app = mcp.sse_app(transport_security=security, host=settings.host)
    else:
        app = mcp.streamable_http_app(streamable_http_path=settings.http_path, transport_security=security,
                                      host=settings.host)
    if not settings.protected_mode and settings.host not in ("127.0.0.1", "localhost", "::1"):
        log.warning("HTTP server on %s without PROTECTED_MODE: anyone who can reach it can run backends!",
                    settings.host)
    uvicorn.run(auth.APIKeyASGIMiddleware(app), host=settings.host, port=settings.port,
                log_level=settings.log_level.lower(), access_log=False)


def _keys(args) -> None:
    from . import storage
    from .logs import auth_event, setup_logging
    setup_logging()
    storage.init_db()
    if args.keys_cmd == "create":
        key = storage.create_api_key(args.name)
        auth_event("key_created", name=args.name, prefix=key[:10], via="cli")
        print(f"API key for '{args.name}' (shown once, only its hash is stored):\n{key}")
    elif args.keys_cmd == "list":
        for k in storage.list_api_keys():
            state = "revoked" if k["revoked"] else "active"
            print(f"#{k['id']:<3} {k['prefix']}...  {k['name']:<16} {state:<8} created {k['created_at']} "
                  f"last used {k['last_used'] or '-'} ({k['uses']} uses)")
    elif args.keys_cmd == "revoke":
        ok = storage.revoke_api_key(args.id)
        auth_event("key_revoked", id=args.id, ok=ok)
        print("revoked" if ok else "no active key with that id")


def _setup(_args) -> None:
    import shutil
    from . import backends, storage
    from .config import PROJECT_ROOT, settings
    settings.ensure_dirs()
    storage.init_db()
    env = PROJECT_ROOT / ".env"
    if not env.exists() and (PROJECT_ROOT / ".env.example").exists():
        shutil.copy2(PROJECT_ROOT / ".env.example", env)
        print(f"created {env} from .env.example")
    done = backends.install_luau_binaries()
    if done:
        print("installed Luau runtime:\n  " + "\n  ".join(done))
    elif not backends.runtime_path("luau"):
        print("Luau binaries not found. Download luau + luau-ast from https://github.com/luau-lang/luau/releases "
              "(or build the patched one: python Tools/deobf_v14_7_v14_8_v14_9_full_fixed_v26/build_luau.py), "
              "put them in a folder and set LUAU_DIR in .env, then rerun setup.")
    print(f"folders ready under {settings.workspace_dir}, {settings.log_dir}, {settings.storage_dir}")
    _doctor(_args)


def _doctor(_args) -> None:
    from . import backends
    from .config import settings
    print(f"protected_mode = {settings.protected_mode}   transport = {settings.transport}")
    print(f"tools_dir      = {settings.tools_dir}  (exists: {settings.tools_dir.is_dir()})")
    print(f"data_dir       = {settings.data_dir}  (exists: {settings.data_dir.is_dir()})")
    print("\nruntimes:")
    for rt, info in backends.runtimes_report().items():
        print(f"  {rt:<7} {info['path'] or 'NOT FOUND  -> ' + info['hint']}")
    print("\nbackends:")
    for b in backends.catalog():
        mark = "OK  " if b["available"] else "MISS"
        print(f"  [{mark}] {b['id']:<16} {b['name']}")
        for m in b["missing"]:
            print(f"           - {m}")
    if "--json" in sys.argv:
        print(json.dumps(backends.catalog(), indent=2))


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(prog="luactopus_mcp", description="Luactopus Lua deobfuscation MCP server")
    sub = ap.add_subparsers(dest="cmd")
    s = sub.add_parser("serve", help="run the MCP server (default)")
    s.add_argument("--transport", choices=["stdio", "streamable-http", "http", "sse"])
    s.add_argument("--host")
    s.add_argument("--port", type=int)
    g = s.add_mutually_exclusive_group()
    g.add_argument("--protected", dest="protected", action="store_true", default=None)
    g.add_argument("--unprotected", dest="protected", action="store_false")
    k = sub.add_parser("keys", help="manage API keys")
    ks = k.add_subparsers(dest="keys_cmd", required=True)
    kc = ks.add_parser("create")
    kc.add_argument("name", nargs="?", default="default")
    ks.add_parser("list")
    kr = ks.add_parser("revoke")
    kr.add_argument("id", type=int)
    sub.add_parser("setup", help="create folders/.env and install luau binaries")
    d = sub.add_parser("doctor", help="check runtimes and backends")
    d.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    if args.cmd in (None, "serve"):
        if args.cmd is None:
            args = ap.parse_args(["serve"])
        _serve(args)
    elif args.cmd == "keys":
        _keys(args)
    elif args.cmd == "doctor":
        _doctor(args)
    elif args.cmd == "setup":
        _setup(args)


if __name__ == "__main__":
    main()
