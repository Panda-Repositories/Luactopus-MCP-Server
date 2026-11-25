from __future__ import annotations

import asyncio
import importlib.util
import os
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .config import settings
from .logs import action, log


LURAPH_ROOT = "deobf_v14_7_v14_8_v14_9_full_fixed_v26"


@dataclass
class RunContext:
    backend: "Backend"
    root: Path
    work: Path
    input_path: Path
    output_path: Path
    timeout: int
    options: dict[str, Any]


@dataclass
class Backend:
    id: str
    name: str
    family: str
    base: str
    rel_root: str
    runtimes: tuple[str, ...]
    dynamic: bool
    description: str
    entry: str = ""
    command: Callable[[RunContext], list[str]] | None = None
    builtin: Callable[[str, RunContext], str] | None = None
    output_name: str = "deobfuscated.lua"
    input_name: str = "input.lua"
    copy_root: bool = False
    env: Callable[[RunContext], dict[str, str]] | None = None
    heavy: bool = False
    needs_files: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    notes: str = ""
    extra: dict = field(default_factory=dict)

    def original_root(self) -> Path:
        base = {"tools": settings.tools_dir, "data": settings.data_dir,
                "custom": settings.custom_tools_dir}[self.base]
        return (base / self.rel_root).resolve()

    def override_root(self) -> Path:
        return (settings.overrides_dir / self.id).resolve()

    def has_override(self) -> bool:
        return self.base != "custom" and self.override_root().is_dir()

    def root(self, use_override: bool = True) -> Path:
        if use_override and self.has_override():
            return self.override_root()
        return self.original_root()

    def missing(self, use_override: bool = True) -> list[str]:
        out: list[str] = []
        root = self.root(use_override)
        if not root.exists():
            out.append(f"tool directory not found: {root}")
        elif self.entry and not (root / self.entry).exists():
            out.append(f"entry file not found: {root / self.entry}")
        else:
            for f in self.needs_files:
                fp = root / (f + (".exe" if os.name == "nt" and f.startswith("bin/") else ""))
                if not fp.exists():
                    out.append(f"missing {fp} (run: python -m luactopus_mcp setup)")
        for rt in self.runtimes:
            if not runtime_path(rt):
                out.append(f"runtime '{rt}' not found ({RUNTIME_HINTS.get(rt, '')})")
        if self.dynamic and not settings.allow_dynamic_backends:
            out.append("dynamic backends disabled (ALLOW_DYNAMIC_BACKENDS=false)")
        return out

    def describe(self) -> dict[str, Any]:
        miss = self.missing()
        return {
            "id": self.id, "name": self.name, "family": self.family, "description": self.description,
            "dynamic": self.dynamic, "runtimes": list(self.runtimes), "available": not miss,
            "missing": miss, "root": str(self.root()), "entry": self.entry,
            "override_active": self.has_override(), "tags": list(self.tags), "notes": self.notes,
        }


RUNTIME_HINTS = {
    "node": "install Node.js 18+ or set NODE_BIN",
    "python": "set PYTHON_BIN",
    "lua": "install Lua 5.3/5.4 and set LUA_BIN",
    "lune": "install Lune (https://github.com/lune-org/lune) and set LUNE_BIN",
    "luau": "put luau(.exe) + luau-ast(.exe) in LUAU_DIR or the tool's bin/ folder, or on PATH",
}


def _luau_exe() -> str:
    return "luau.exe" if os.name == "nt" else "luau"


def luau_sources() -> list[Path]:
    out = []
    if settings.luau_dir:
        out.append(Path(settings.luau_dir))
    out.append(settings.data_dir / "flowauth" / "vendor" / "luraph151" / "bin")
    return out


def install_luau_binaries(dest_roots: list[Path] | None = None) -> list[str]:
    names = ["luau.exe", "luau-ast.exe"] if os.name == "nt" else ["luau", "luau-ast"]
    src_dir = next((d for d in luau_sources() if all((d / n).is_file() for n in names)), None)
    if src_dir is None:
        return []
    dest_roots = dest_roots or [settings.tools_dir / LURAPH_ROOT] + [
        settings.overrides_dir / i for i in ("ib1", "luraph147", "luraph148", "luraph149", "luraph15", "envtrace")]
    done = []
    for root in dest_roots:
        if not root.is_dir():
            continue
        (root / "bin").mkdir(exist_ok=True)
        for n in names:
            dst = root / "bin" / n
            if not dst.exists():
                shutil.copy2(src_dir / n, dst)
                if os.name != "nt":
                    dst.chmod(0o755)
                done.append(str(dst))
    return done


def runtime_path(name: str) -> str | None:
    if name == "node":
        return shutil.which(settings.node_bin) or (settings.node_bin if Path(settings.node_bin).is_file() else None)
    if name == "python":
        return settings.python_bin if Path(settings.python_bin).exists() else shutil.which(settings.python_bin)
    if name == "lua":
        b = settings.lua_bin
        return (b if b and Path(b).exists() else shutil.which(b)) if b else None
    if name == "lune":
        b = settings.lune_bin
        return (b if b and Path(b).exists() else shutil.which(b)) if b else None
    if name == "luau":
        candidates = []
        if settings.luau_dir:
            candidates.append(Path(settings.luau_dir) / _luau_exe())
        candidates.append(settings.tools_dir / LURAPH_ROOT / "bin" / _luau_exe())
        candidates += [d / _luau_exe() for d in luau_sources()]
        for c in candidates:
            if c.is_file():
                return str(c)
        return shutil.which(_luau_exe())
    return shutil.which(name)


def _env_with_luau() -> dict[str, str]:
    env = os.environ.copy()
    extra = []
    if settings.luau_dir:
        extra.append(settings.luau_dir)
    lua = runtime_path("lua")
    if lua:
        extra.append(str(Path(lua).parent))
    lune = runtime_path("lune")
    if lune:
        extra.append(str(Path(lune).parent))
    if extra:
        env["PATH"] = os.pathsep.join(extra + [env.get("PATH", "")])
    env.setdefault("PYTHONIOENCODING", "utf-8")
    env["PYTHON_BIN"] = settings.python_bin
    return env


def heavy_timeout(source: str) -> int:
    size_mb = max(1, (len(source.encode("utf-8", "ignore")) + 999_999) // 1_000_000)
    return max(settings.default_timeout, min(settings.max_timeout, 180 + size_mb * 90))


def _node(ctx: RunContext, script: str, *args: str) -> list[str]:
    return [runtime_path("node") or "node", str(ctx.root / script), *args]


def _py(ctx: RunContext, script: str, *args: str) -> list[str]:
    return [settings.python_bin, str(ctx.root / script), *args]


def cmd_prometheus(ctx):
    a = [str(ctx.input_path), "-o", str(ctx.output_path)]
    if ctx.options.get("force"):
        a.append("--force")
    return _node(ctx, "bin/pdeobf.js", *a)


def cmd_clyde(ctx):
    return _node(ctx, "cli.js", str(ctx.input_path), "-o", str(ctx.output_path))


def cmd_goofy_v11(ctx):
    a = [str(ctx.input_path), "-o", str(ctx.output_path)]
    if runtime_path("lua"):
        a += ["--lua", runtime_path("lua")]
    if runtime_path("lune"):
        a += ["--lune", runtime_path("lune")]
    if ctx.options.get("engine"):
        a += ["--engine", str(ctx.options["engine"])]
    return _node(ctx, "deobf.js", *a)


def cmd_goofy_v10(ctx):
    a = [str(ctx.input_path), "-o", str(ctx.output_path)]
    if runtime_path("lua"):
        a += ["--lua", runtime_path("lua")]
    if ctx.options.get("no_optimize"):
        a.append("--no-optimize")
    return _node(ctx, "src/cli.js", *a)


def cmd_luaobfuscator(ctx):
    return _node(ctx, "index.js", str(ctx.input_path), "--out", str(ctx.output_path))


def _deob_common(ctx) -> list[str]:
    a = ["--timeout", str(max(120, ctx.timeout // 3))]
    if ctx.options.get("executor"):
        a += ["--executor", str(ctx.options["executor"])]
    if ctx.options.get("no_devirt"):
        a.append("--no-devirt")
    if ctx.options.get("strings"):
        a.append("--strings")
    for kv in ctx.options.get("cfg", []) or []:
        a += ["--cfg", str(kv)]
    return a


def cmd_deob_plugin(plugin: str):
    def build(ctx):
        a = [str(ctx.input_path), "-o", str(ctx.output_path), "--obfuscator", plugin, *_deob_common(ctx)]
        if ctx.options.get("no_pypy"):
            a.append("--no-pypy")
        return _py(ctx, "deob.py", *a)
    return build


def cmd_luraph14(engine: str):
    def build(ctx):
        a = [str(ctx.input_path), "-o", str(ctx.output_path), "--engine", engine,
             "--timeout", str(max(120, ctx.timeout // 3))]
        if ctx.options.get("no_devirt"):
            a.append("--no-devirt")
        if ctx.options.get("executor"):
            a += ["--executor", str(ctx.options["executor"])]
        return _py(ctx, "cli.py", *a)
    return build


def cmd_ib2(ctx):
    return [settings.python_bin, str(ctx.work / "processor.py")]


def cmd_luraph151(ctx):
    a = [str(ctx.input_path), "-o", str(ctx.output_path), "--timeout", str(ctx.timeout)]
    if ctx.options.get("no_devirt"):
        a.append("--no-devirt")
    if ctx.options.get("devirt_rounds"):
        a += ["--devirt-rounds", str(ctx.options["devirt_rounds"])]
    return _node(ctx, "deob.js", *a)


def cmd_oxygen_l2(ctx):
    return [runtime_path("lune") or "lune", "run", str(ctx.root / "l2.lua"), str(ctx.input_path),
            str(ctx.output_path)]


def env_oxygen(ctx):
    p = {"place_id": 1818, "game_id": 6767, "user_name": "Player", "display_name": "Player", "user_id": 1,
         "locale": "en-us", "membership_type": "None", "executor_name": "Madium"}
    p.update({k: v for k, v in (ctx.options.get("profile") or {}).items() if k in p})
    env = _env_with_luau()
    env.update({"ROBLOX_PLACE_ID": str(p["place_id"]), "ROBLOX_GAME_ID": str(p["game_id"]),
                "ROBLOX_USERNAME": str(p["user_name"]), "ROBLOX_DISPLAY_NAME": str(p["display_name"]),
                "ROBLOX_USER_ID": str(p["user_id"]), "ROBLOX_LOCALE": str(p["locale"]),
                "ROBLOX_MEMBERSHIP_TYPE": str(p["membership_type"]),
                "ROBLOX_EXECUTOR_NAME": str(p["executor_name"]), "DISCORD_USER_ID": "0"})
    return env


def builtin_ib3(source: str, ctx: RunContext) -> str:
    path = ctx.root / "deobfuscator.py"
    spec = importlib.util.spec_from_file_location(f"luactopus_ib3_{abs(hash(str(path)))}", path)
    if not spec or not spec.loader:
        raise RuntimeError(f"cannot load {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    parsed = mod.parse_ib3(source)
    root = mod.find_root(parsed.prototypes)
    lines = ["-- IronBrew 3 decoded VM program", f"-- profile: {parsed.profile}",
             f"-- constants: {len(parsed.constants)}", f"-- prototypes: {len(parsed.prototypes)}",
             f"-- root candidate: {root}", "", "-- constants table", "local K = {"]
    for i, k in enumerate(parsed.constants):
        lines.append(f"    [{i}] = {k!r},")
    lines += ["}", "", "-- Randomised opcode semantics are emitted as IR comments.", ""]
    for i, fn in enumerate(parsed.prototypes):
        lines += [f"-- prototype {i} params={fn.params}", f"local function fn_{i}(...)"]
        for pc, x in enumerate(fn.instructions, 1):
            lines.append(f"    -- [{pc}] opcode={x.opcode} a={x.a} b={x.b} c={x.c} jump={x.jump} extra={x.extra!r}")
        lines += ["end", ""]
    lines.append(f"return fn_{root}(...)")
    return "\n".join(lines)


LUAU_BINS = ("bin/luau", "bin/luau-ast")

BACKENDS: dict[str, Backend] = {}


def register(b: Backend) -> Backend:
    BACKENDS[b.id] = b
    return b


register(Backend(
    id="prometheus", name="Prometheus", family="prometheus", base="tools", rel_root="son",
    entry="bin/pdeobf.js", runtimes=("node",), dynamic=False, command=cmd_prometheus,
    output_name="out.lua", input_name="script.lua",
    description="Static Prometheus deobfuscator (wrap/fold/string decode + beautify). Options: force=True skips detection."))
register(Backend(
    id="clyde", name="Clyde Protection", family="clyde", base="tools", rel_root="tuff/idk",
    entry="cli.js", runtimes=("node",), dynamic=False, command=cmd_clyde,
    output_name="clean.lua", input_name="obfuscated.lua",
    description="Static deobfuscator for Clyde Protection-obfuscated Luau (symbolic VM lift)."))
register(Backend(
    id="goofyscator", name="Goofyscator V11 (recovery)", family="goofyscator", base="tools",
    rel_root="goofyscator_v11_recovery_v2", entry="deobf.js", runtimes=("node",), dynamic=True,
    command=cmd_goofy_v11, heavy=True,
    description="Goofyscator V11 behaviour recovery: runs the script under Lua 5.4/Lune and writes a partial "
                "dynamic trace. Needs LUA_BIN or LUNE_BIN for real results. Option engine='lua'|'lune'.",
    notes="Exit code 0 even when recovery is incomplete - read the RECOVERY STATUS header."))
register(Backend(
    id="goofyscator_v10", name="Goofyfuscator V10 devirtualizer", family="goofyscator", base="tools",
    rel_root="goofyscator", entry="src/cli.js", runtimes=("node",), dynamic=True,
    command=cmd_goofy_v10, heavy=True,
    description="Polymorphic Goofyfuscator V10 VM devirtualizer with structured Lua recovery. "
                "Uses a Lua runtime for VM capture. Option no_optimize=True."))
register(Backend(
    id="luaobfuscator", name="LuaObfuscator.com", family="luaobfuscator", base="tools",
    rel_root="LuaObfuscator-Deobfuscator", entry="index.js", runtimes=("node",), dynamic=False,
    command=cmd_luaobfuscator,
    description="LuaObfuscator (chaotic good/evil, IB2-family VM) static devirtualizer."))
register(Backend(
    id="ib1", name="IronBrew 1", family="ironbrew1", base="tools", rel_root=LURAPH_ROOT, entry="deob.py",
    runtimes=("python",), dynamic=True, command=cmd_deob_plugin("ironbrew1"), heavy=True, needs_files=LUAU_BINS,
    description="IronBrew 1 via the unified deob.py (plugin ironbrew1): trace + devirtualize in the Luau VM."))
register(Backend(
    id="ib2", name="IronBrew 2 / AztupBrew", family="ironbrew2", base="tools", rel_root="ironbrew2-deobfuscator",
    entry="processor.py", runtimes=("python",), dynamic=False, command=cmd_ib2, copy_root=True,
    output_name="restored.lua", input_name="input.lua", heavy=True,
    description="IronBrew 2 / AztupBrew AST-level deobfuscator (needs the luaparser Python package)."))
register(Backend(
    id="ib3", name="IronBrew 3", family="ironbrew3", base="tools", rel_root=".", entry="deobfuscator.py",
    runtimes=(), dynamic=False, builtin=builtin_ib3,
    description="IronBrew 3 serialized-payload parser: decodes constants and prototypes to an IR listing "
                "(opcode semantics stay as comments)."))
for _ver, _id in (("14.7", "luraph147"), ("14.8", "luraph148"), ("14.9", "luraph149")):
    register(Backend(
        id=_id, name=f"Luraph v{_ver}", family="luraph", base="tools", rel_root=LURAPH_ROOT, entry="cli.py",
        runtimes=("python",), dynamic=True, command=cmd_luraph14(_ver), heavy=True, needs_files=LUAU_BINS,
        description=f"Luraph v{_ver} devirtualizer (cli.py --engine {_ver}). Options: no_devirt, executor."))
register(Backend(
    id="luraph15", name="Luraph v15", family="luraph", base="tools", rel_root=LURAPH_ROOT, entry="deob.py",
    runtimes=("python",), dynamic=True, command=cmd_deob_plugin("luraph_v15"), heavy=True, needs_files=LUAU_BINS,
    description="Luraph v15 dynamic devirtualizer (deob.py --obfuscator luraph_v15). Options: no_devirt, "
                "strings, executor, cfg=['KEY=VALUE'], no_pypy."))
register(Backend(
    id="envtrace", name="Generic behaviour trace", family="generic", base="tools", rel_root=LURAPH_ROOT,
    entry="deob.py", runtimes=("python",), dynamic=True, command=cmd_deob_plugin("generic"), heavy=True,
    needs_files=LUAU_BINS,
    tags=("fallback",),
    description="Fallback for unknown obfuscators: runs the script in the real Luau VM against a fake "
                "Roblox/executor environment (envlog.luau) and renders everything it did back as Luau."))
register(Backend(
    id="oxygen", name="Oxygen env logger (L2)", family="envlogger", base="tools", rel_root=".", entry="l2.lua",
    runtimes=("lune",), dynamic=True, command=cmd_oxygen_l2, env=env_oxygen, output_name="output.lua",
    tags=("fallback",),
    description="Radium/Oxygen L2 environment logger running under Lune: dumps every API call the script "
                "makes. Option profile={place_id, game_id, user_name, user_id, executor_name, ...}."))
register(Backend(
    id="luraph151", name="Luraph v15.1 (ServerDeadd, from Data/)", family="luraph", base="data",
    rel_root="flowauth/vendor/luraph151", entry="deob.js", runtimes=("node", "python"), dynamic=True,
    command=cmd_luraph151, heavy=True,
    description="External Luraph v15/v15.1 devirtualizer vendored in Data/flowauth/vendor. Ships its own "
                "luau binaries. Options: no_devirt, devirt_rounds."))


def get(backend_id: str) -> Backend:
    b = BACKENDS.get(backend_id)
    if not b:
        load_custom_backends()
        b = BACKENDS.get(backend_id)
    if not b:
        raise KeyError(f"unknown backend {backend_id!r}; known: {', '.join(sorted(BACKENDS))}")
    return b


def load_custom_backends() -> None:
    import json
    root = settings.custom_tools_dir
    if not root.is_dir():
        return
    for d in root.iterdir():
        meta_p = d / "tool.json"
        if not meta_p.is_file():
            continue
        try:
            meta = json.loads(meta_p.read_text(encoding="utf-8"))
        except Exception:
            continue
        bid = "custom:" + d.name
        lang = meta.get("language", "python")
        entry = meta.get("entry", "main.py" if lang == "python" else "main.js" if lang == "node" else "main.lua")

        def build(ctx, lang=lang, entry=entry):
            exe = {"python": settings.python_bin, "node": runtime_path("node") or "node",
                   "lua": runtime_path("lua") or "lua", "lune": runtime_path("lune") or "lune"}[lang]
            pre = ["run"] if lang == "lune" else []
            return [exe, *pre, str(ctx.root / entry), str(ctx.input_path), str(ctx.output_path)]

        BACKENDS[bid] = Backend(
            id=bid, name=meta.get("name", d.name), family=meta.get("family", "custom"), base="custom",
            rel_root=d.name, entry=entry, runtimes=(lang,), dynamic=bool(meta.get("dynamic", False)),
            command=build, description=meta.get("description", "custom tool written via MCP"),
            tags=("custom",))


@dataclass
class RunResult:
    backend: str
    ok: bool
    output: str
    stdout: str
    stderr: str
    returncode: int | None
    seconds: float
    error: str | None
    work_dir: str
    command: list[str]
    override: bool

    def summary(self, tail: int = 1500) -> dict[str, Any]:
        return {"backend": self.backend, "ok": self.ok, "returncode": self.returncode,
                "seconds": round(self.seconds, 2), "error": self.error, "override": self.override,
                "output_chars": len(self.output), "stdout_tail": self.stdout[-tail:],
                "stderr_tail": self.stderr[-tail:], "work_dir": self.work_dir, "command": self.command}


def _read_text(path: Path) -> str:
    data = path.read_bytes()
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1")


async def _run_process(args: list[str], *, cwd: Path, env: dict[str, str] | None, timeout: int):
    flags = 0x08000000 if os.name == "nt" else 0
    proc = await asyncio.create_subprocess_exec(
        *args, cwd=str(cwd), env=env, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        stdin=asyncio.subprocess.DEVNULL, creationflags=flags)
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        try:
            await proc.communicate()
        except Exception:
            pass
        raise TimeoutError(f"timed out after {timeout}s")
    return proc.returncode, out.decode("utf-8", "replace"), err.decode("utf-8", "replace")


async def run_backend(backend_id: str, source: str, run_dir: Path, *, timeout: int | None = None,
                      use_override: bool = True, options: dict[str, Any] | None = None,
                      job_id: str | None = None) -> RunResult:
    b = get(backend_id)
    options = options or {}
    root = b.root(use_override)
    override = use_override and b.has_override()
    run_dir.mkdir(parents=True, exist_ok=True)
    timeout = min(int(timeout or (heavy_timeout(source) if b.heavy else settings.default_timeout)),
                  settings.max_timeout)
    started = time.perf_counter()
    miss = b.missing(use_override)
    if miss:
        res = RunResult(b.id, False, "", "", "", None, 0.0, "backend unavailable: " + "; ".join(miss),
                        str(run_dir), [], override)
        action("backend_unavailable", job_id=job_id, backend=b.id, missing=miss)
        return res

    work = run_dir
    if b.copy_root:
        work = run_dir / "tool"
        if work.exists():
            shutil.rmtree(work)
        shutil.copytree(root, work, ignore=shutil.ignore_patterns("__pycache__", ".git", "node_modules"))
        root_for_cmd = work
    else:
        root_for_cmd = root
    input_path = work / b.input_name
    output_path = work / b.output_name
    input_path.write_text(source, encoding="utf-8", errors="replace")
    ctx = RunContext(b, root_for_cmd, work, input_path, output_path, timeout, options)

    cmd: list[str] = []
    stdout = stderr = ""
    rc: int | None = None
    error = None
    output = ""
    try:
        if b.builtin:
            output = await asyncio.wait_for(asyncio.to_thread(b.builtin, source, ctx), timeout=timeout)
            output_path.write_text(output, encoding="utf-8")
            rc = 0
        else:
            assert b.command is not None
            cmd = b.command(ctx)
            env = b.env(ctx) if b.env else _env_with_luau()
            cwd = work if b.copy_root else root
            action("backend_start", job_id=job_id, backend=b.id, command=cmd, cwd=str(cwd), timeout=timeout,
                   override=override)
            rc, stdout, stderr = await _run_process(cmd, cwd=cwd, env=env, timeout=timeout)
            if output_path.exists():
                output = _read_text(output_path)
            if rc != 0:
                error = (stderr.strip() or stdout.strip() or f"exit code {rc}")[-3000:]
            elif not output_path.exists():
                error = f"finished without creating {output_path.name}"
            elif not output.strip():
                error = "empty output"
    except TimeoutError as exc:
        error = str(exc)
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
        log.exception("backend %s crashed", b.id)
    seconds = time.perf_counter() - started
    (run_dir / "stdout.txt").write_text(stdout, encoding="utf-8")
    (run_dir / "stderr.txt").write_text(stderr, encoding="utf-8")
    ok = error is None and bool(output.strip())
    action("backend_done", job_id=job_id, backend=b.id, ok=ok, returncode=rc, seconds=round(seconds, 2),
           error=error, output_chars=len(output))
    return RunResult(b.id, ok, output, stdout, stderr, rc, seconds, error, str(run_dir), cmd, override)


def catalog() -> list[dict[str, Any]]:
    load_custom_backends()
    return [b.describe() for b in BACKENDS.values()]


def runtimes_report() -> dict[str, Any]:
    return {rt: {"path": runtime_path(rt), "hint": RUNTIME_HINTS[rt]} for rt in RUNTIME_HINTS}
