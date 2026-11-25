# Luactopus MCP Server

An MCP server that deobfuscates Lua / Luau (mostly Roblox) scripts. It uses the deobfuscators from
the Radium Discord bot (`Tools/`), runs them layer by layer until the result is human-readable, and lets
the connected AI read, fork and patch a tool when it fails.

```
your AI client ──MCP──► Luactopus ──► identify ─► run backend ─► validate ─► readable? ──no──► next layer
                             │                                                 │
                             │                         yes ◄───────────────────┘
                             ├── logs/       everything received and done
                             ├── workspace/  jobs, patched tool copies, custom tools
                             └── storage/    SQLite: API keys, run history, learned fingerprints
```

## Features

- **13 backends** dissected from `Tools/bot.py`, behind one interface (see the [table](#backends)).
- **Auto-identification:** marker rules from the bot, the bot's fingerprint DB, fingerprints you teach it, and run history. Backends that worked before on similar scripts are ranked higher.
- **Layered pipeline:** detect → try ranked backends → validate the Lua → accept only if readability improves → repeat. It stops at a readability score of 70+ (default), or when nothing improves any more.
- **Static cleanup:** folds `string.char(...)`, decodes `\ddd`/`\xHH` strings (UTF-8 aware), folds literal concatenation and re-indents. It never executes code.
- **Self-repair:** the AI can list, read and search a backend's source. `fork_tool` and `edit_tool_file` patch a private copy in `workspace/overrides/`, and later runs use that copy automatically. `create_custom_tool` adds a brand-new pass. The originals in `Tools/` are never modified.
- **Knowledge base:** `Data/` (env-logger research, anti-tamper samples, key-system analysis) is indexed for `search_knowledge` / `read_knowledge`.
- **Key-system loaders** (FlowAuth, Panda, Luarmor-style): offline structure report plus the FlowAuth LPH transport decode. It does **not** bypass key checks (see [below](#key-systems)).
- **Protected Mode:** API keys hashed in SQLite. Off by default.
- **Full logging:** every MCP message, every subprocess, every file edit and every auth decision, as JSONL in `logs/`.

## Requirements

| Needed for | Install |
|---|---|
| the server | **Python 3.10+** (tested on 3.14) |
| Prometheus, Clyde, Goofyscator, LuaObfuscator, Luraph 15.1 | **Node.js 18+** (20+ for Goofyscator) |
| Luraph 14.7 – 15, IronBrew 1, behaviour trace | **Luau** `luau` + `luau-ast` binaries. `setup` installs them automatically from `Data/flowauth/vendor/luraph151/bin` when that folder exists |
| Goofyscator VM capture (optional) | **Lua 5.3/5.4** → `LUA_BIN` |
| Oxygen env logger, Goofyscator lune engine (optional) | **[Lune](https://github.com/lune-org/lune)** → `LUNE_BIN` |

## Setup

### 1. Install

Windows (PowerShell):

```powershell
cd "Luactopus MCP Server"
python -m venv .venv
.\.venv\Scripts\python -m pip install -r requirements.txt
.\.venv\Scripts\python -m luactopus_mcp setup
```

Linux / macOS:

```bash
cd "Luactopus MCP Server"
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m luactopus_mcp setup
```

`setup` creates `.env` from `.env.example`, creates the `logs/`, `workspace/` and `storage/` folders,
installs the Luau binaries into the Luraph tool's `bin/`, and prints a doctor report:

```
runtimes:
  node    C:\Program Files\nodejs\node.EXE
  python  ...\.venv\Scripts\python.exe
  lua     NOT FOUND  -> install Lua 5.3/5.4 and set LUA_BIN
  lune    NOT FOUND  -> install Lune (https://github.com/lune-org/lune) and set LUNE_BIN
  luau    ...\Tools\deobf_v14_7_v14_8_v14_9_full_fixed_v26\bin\luau.exe
backends:
  [OK  ] prometheus       Prometheus
  ...
  [MISS] oxygen           Oxygen env logger (L2)
```

You can rerun `python -m luactopus_mcp doctor` at any time. If no Luau binaries are found, download
`luau` + `luau-ast` from the [Luau releases](https://github.com/luau-lang/luau/releases), or build the
patched runtime with `python Tools/deobf_v14_7_v14_8_v14_9_full_fixed_v26/build_luau.py`. Put them in a
folder, set `LUAU_DIR` in `.env`, and run `setup` again.

### 2. Configure `.env`

Every option is documented in [.env.example](.env.example). The ones that matter most:

| Variable | Default | Meaning |
|---|---|---|
| `MCP_TRANSPORT` | `stdio` | `stdio` (the client starts the server) or `streamable-http` / `sse` (you start it) |
| `PROTECTED_MODE` | `false` | `true` requires an API key |
| `TOOLS_DIR`, `DATA_DIR` | `./Tools`, `./Data` | where the backends and the knowledge base live |
| `LUA_BIN`, `LUNE_BIN`, `LUAU_DIR` | auto | runtimes |
| `ALLOW_TOOL_EDITS` | `true` | the AI may fork and patch backends |
| `ALLOW_CUSTOM_TOOLS` | `true` | the AI may add new backends (this is code execution) |
| `ALLOW_DYNAMIC_BACKENDS` | `true` | backends that run the script in an emulated environment |
| `ALLOW_LOCAL_PATHS` | `true` on stdio, `false` on HTTP | tools may read `file_path` arguments from disk |

### 3. Connect your AI client

The server finds its folders from its own location, so the working directory does not matter. Use the
virtualenv's Python with absolute paths.

**Claude Code:**

```bash
claude mcp add luactopus -- "C:/path/to/Luactopus MCP Server/.venv/Scripts/python.exe" -m luactopus_mcp
```

**Claude Desktop** (`claude_desktop_config.json`), **Cursor** (`.cursor/mcp.json`) and other stdio clients:

```json
{
  "mcpServers": {
    "luactopus": {
      "command": "C:/path/to/Luactopus MCP Server/.venv/Scripts/python.exe",
      "args": ["-m", "luactopus_mcp"],
      "env": { "LUACTOPUS_API_KEY": "" }
    }
  }
}
```

**HTTP** (one server shared by several clients):

```bash
python -m luactopus_mcp serve --transport streamable-http --host 127.0.0.1 --port 8765
# endpoint: http://127.0.0.1:8765/mcp     health: http://127.0.0.1:8765/health
```

For clients that support remote servers, such as Claude Code's `.mcp.json`:

```json
{ "mcpServers": { "luactopus": { "type": "http", "url": "http://127.0.0.1:8765/mcp",
  "headers": { "Authorization": "Bearer lct_..." } } } }
```

## Protected Mode

| | `PROTECTED_MODE=false` (default) | `PROTECTED_MODE=true` |
|---|---|---|
| HTTP | no key needed | every request needs `Authorization: Bearer <key>` or `X-API-Key: <key>`, otherwise 401 |
| stdio | no key needed | the server exits unless `LUACTOPUS_API_KEY` in its env is a valid key |

On the first start in protected mode, the server creates a key automatically and stores its SHA-256
hash in SQLite (`storage/luactopus.db`). The plaintext key is shown **once**: on the console and in
`storage/FIRST_API_KEY.txt`. Copy it into your client config, then delete that file.

```bash
python -m luactopus_mcp keys create my-laptop   # new key, printed once
python -m luactopus_mcp keys list               # id, prefix, last used, uses
python -m luactopus_mcp keys revoke 2
```

If you bind HTTP to anything other than localhost, turn Protected Mode on. Also set `MCP_ALLOWED_HOSTS`
to the host names clients use, so DNS-rebinding protection accepts them.

## Using it

Ask your AI something like *"Deobfuscate C:\scripts\hub.lua with Luactopus until it's readable"*, or use
the built-in prompt `deobfuscate_until_readable`. A typical session:

1. `server_status`: shows which backends can run here.
2. `identify_obfuscator`: ranked backends, readability score, key-system and loader-stub flags.
3. `deobfuscate`: the layered pipeline. It returns a `job_id`, the attempts for each layer, readability before and after, a preview and `next_steps`.
4. `read_job_file(job_id, "final.lua")`: the full result.
5. When a backend fails: `read_job_file(job_id, "layer1_<backend>/stderr.txt")`, then `search_tool_code` / `read_tool_file`, then `edit_tool_file`, then `run_backend(..., job_id=..., job_file="input.lua")`. `diff_tool` shows the patch and `reset_tool` reverts it. The prompt `repair_backend` walks through this.
6. `teach_fingerprint` and `record_feedback`: the detector ranks the right backend first next time.

### Tools

| Group | Tools |
|---|---|
| Status | `server_status`, `list_backends` |
| Analysis | `identify_obfuscator`, `analyze_readability`, `analyze_key_system` |
| Deobfuscation | `deobfuscate`, `run_backend`, `cleanup_lua` |
| Jobs | `list_jobs`, `list_job_files`, `read_job_file` |
| Tool repair | `list_tool_files`, `read_tool_file`, `search_tool_code`, `fork_tool`, `edit_tool_file`, `write_tool_file`, `diff_tool`, `reset_tool`, `create_custom_tool` |
| Knowledge | `search_knowledge`, `list_knowledge`, `read_knowledge` |
| Learning | `teach_fingerprint`, `record_feedback`, `learning_stats`, `forget_fingerprint` |

Resources: `luactopus://backends`, `luactopus://knowledge`, `luactopus://guide`.
Prompts: `deobfuscate_until_readable`, `repair_backend`.

Scripts can be passed as `script` (text), `file_path` (local file) or `job_id` + `job_file` (a file from
an earlier job, for example `final.lua` to run another layer).

### Backends

Each backend wraps a `run_*` function from `Tools/bot.py`:

| id | Obfuscator | Code | Runtime | Runs the script? |
|---|---|---|---|---|
| `prometheus` | Prometheus / WeAreDevs | `Tools/son` | node | no |
| `clyde` | Clyde Protection | `Tools/tuff/idk` | node | no |
| `goofyscator_v10` | Goofyfuscator V10 | `Tools/goofyscator` | node (+ lua) | yes (VM capture) |
| `goofyscator` | Goofyscator V11 | `Tools/goofyscator_v11_recovery_v2` | node (+ lua/lune) | yes (trace) |
| `luaobfuscator` | LuaObfuscator.com | `Tools/LuaObfuscator-Deobfuscator` | node | no |
| `ib1` | IronBrew 1 | `Tools/deobf_v14_7_…_v26` (`deob.py --obfuscator ironbrew1`) | python + luau | yes |
| `ib2` | IronBrew 2 / AztupBrew | `Tools/ironbrew2-deobfuscator` | python (luaparser) | no |
| `ib3` | IronBrew 3 | `Tools/deobfuscator.py` | in-process | no |
| `luraph147` / `luraph148` / `luraph149` | Luraph v14.x | `cli.py --engine 14.x` | python + luau | yes |
| `luraph15` | Luraph v15 | `deob.py --obfuscator luraph_v15` | python + luau | yes |
| `luraph151` | Luraph v15/15.1 (external) | `Data/flowauth/vendor/luraph151` | node + python | yes |
| `envtrace` | anything (fallback) | `deob.py --obfuscator generic` | python + luau | yes |
| `oxygen` | anything (env logger) | `Tools/l2.lua` | lune | yes |
| `custom:<name>` | whatever you write | `workspace/custom_tools/<name>` | python/node/lua/lune | your choice |

The Discord-specific parts of the bot were not ported: embeds and buttons, premium and channel gating,
the LootLabs/Linkvertise gate, and the `fetch`/`get`/Nexomia commands that spoof Roblox client headers
to pull loader payloads.

> **Dynamic backends run the protected script** inside an emulated Roblox/executor environment. These
> environments are not security sandboxes. Run untrusted scripts on a VM or in a container, or set
> `ALLOW_DYNAMIC_BACKENDS=false`.

### Key systems

`analyze_key_system` reports which key system a loader uses (FlowAuth, Panda, Luarmor, jnkie,
`script_key`), its URLs and API routes, its HTTP transports, the sensitive executor APIs it calls, how
it reads the key, and the vendor's error taxonomy. For FlowAuth/Luraph `LPH` payloads it also runs
`Data/flowauth/flowauth_deobf.py info` and `outer`, which decode the transport to the raw word stream
offline.

It does not contact the vendor, replay or forge sessions, or skip checkpoints. The research in
`Data/flowauth/DEOBFUSCATOR.md` shows that the protected program is bound to a server-signed proof for
each execution. To analyse your own protected scripts, run them through the normal loader with your
own key.

### About "training" on `Data/`

An MCP server cannot retrain the model of the AI that connects to it. Luactopus does two things
instead:

1. **Retrieval:** `Data/` is indexed, so the AI reads the relevant research while it works (`search_knowledge`).
2. **Learning store:** every backend run is recorded in SQLite together with the script's structural features. `teach_fingerprint` adds labelled samples. Detection uses both, so the server's own choices improve with use. `learning_stats` shows what it has learned.

## Logs and files

| Path | Contents |
|---|---|
| `logs/server.log` | human-readable process log (rotating, 10 MB × 5) |
| `logs/requests/<date>.jsonl` | every MCP message: method, parameters, result, duration |
| `logs/actions/<date>.jsonl` | every action: subprocess command lines, job results, tool forks and edits |
| `logs/auth/<date>.jsonl` | key creation, revocation, accepted and denied requests (keys masked) |
| `logs/http/<date>.jsonl` | HTTP access log (HTTP transports only) |
| `workspace/jobs/<job_id>/` | `input.lua`, `layerN.lua`, `final.lua`, `report.json`, and one folder per backend attempt with its output, `stdout.txt` and `stderr.txt` |
| `workspace/overrides/<backend>/` | patched tool copies |
| `workspace/custom_tools/<name>/` | AI-written backends |
| `storage/luactopus.db` | API key hashes, run history, fingerprints, feedback |

Long fields are truncated in the JSONL logs (`LOG_MAX_FIELD_CHARS`). Full scripts and outputs are always
kept in the job folder. `logs/`, `workspace/`, `storage/`, `.env` and `.venv/` are git-ignored.

## Project layout

```
luactopus_mcp/
  __main__.py   CLI: serve | setup | doctor | keys
  server.py     MCP tools, resources, prompts
  config.py     .env loading
  auth.py       Protected Mode (bootstrap key, stdio check, HTTP middleware)
  storage.py    SQLite: keys, runs, fingerprints, feedback
  logs.py       log folders + MCP request middleware
  backends.py   backend registry and runner (ported from bot.py)
  detect.py     obfuscator identification
  pipeline.py   jobs + layered deobfuscation loop
  luatext.py    Lua masking, validation, features, readability, cleanup passes
  toolsmith.py  fork / read / edit / diff / reset tools, custom tools
  knowledge.py  Data/ index and search
  keysys.py     key-system loader analysis
Tools/          the bot and its deobfuscators (unchanged)
Data/           research data (git-ignored)
```

## Troubleshooting

- **A backend shows `[MISS]`:** run `python -m luactopus_mcp doctor`; it names the missing runtime or file.
- **Goofyscator output says `RECOVERY STATUS: INCOMPLETE`:** install Lua 5.4 and set `LUA_BIN` (or Lune and `LUNE_BIN`).
- **Luraph says `attempt to index vector with 'Dot'`:** stock Luau freezes the vector metatable. Build the patched runtime with `build_luau.py`.
- **The stdio client says the server exited at once:** check `logs/server.log`. In protected mode, `LUACTOPUS_API_KEY` is probably missing.
- **HTTP requests from another machine are rejected for their Host header:** add that host name to `MCP_ALLOWED_HOSTS`.
