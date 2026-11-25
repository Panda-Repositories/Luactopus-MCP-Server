from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path
from typing import Any

from .backends import _run_process
from .config import settings
from .detect import key_system_info
from .logs import action

TRANSPORTS = ["game:HttpGet", "HttpGetAsync", "request(", "http_request(", "syn.request", "http.request",
              "fluxus.request", "HttpService:RequestAsync", "HttpService:GetAsync", "WebSocket.connect"]
SENSITIVE = ["writefile", "readfile", "delfile", "appendfile", "makefolder", "setclipboard", "getgenv",
             "getrenv", "hookfunction", "hookmetamethod", "getrawmetatable", "setreadonly", "identifyexecutor",
             "gethwid", "get_hwid", "RbxAnalyticsService", "GetClientId", "queue_on_teleport", "loadstring",
             "Players.LocalPlayer.UserId", "MarketplaceService"]


def _counts(src: str, names: list[str]) -> dict[str, int]:
    out = {}
    low = src.lower()
    for n in names:
        c = low.count(n.lower())
        if c:
            out[n] = c
    return out


def static_report(src: str) -> dict[str, Any]:
    info = key_system_info(src) or {"systems": {}, "urls": []}
    endpoints = sorted(set(re.findall(r"/v\d+/[a-z0-9_/\-]+", src, re.I)))[:60]
    key_reads = sorted(set(m.group(0) for m in re.finditer(
        r"(?:getgenv\(\)\s*\.\s*|_G\s*\.\s*|\b)(?:script_key|Key|key|SCRIPT_KEY)\s*(?:=|==|~=)[^\n]{0,60}", src)))[:20]
    lph = re.search(r"\[(=+)\[(LPH.)", src)
    report = {
        "key_systems": info.get("systems", {}),
        "urls": info.get("urls", []),
        "api_routes": endpoints,
        "transports": _counts(src, TRANSPORTS),
        "sensitive_apis": _counts(src, SENSITIVE),
        "key_handling_snippets": key_reads,
        "luraph_payload": {"marker": lph.group(2), "bracket_level": len(lph.group(1))} if lph else None,
        "size_chars": len(src),
        "error_taxonomy": sorted(set(re.findall(
            r"\b(key_required|key_paused|key_expired|key_revoked|hwid_mismatch|premium_required|nonce_reused|"
            r"challenge_rejected|launch_ticket_rejected|runtime_outdated|checkpoint_not_verified)\b", src))),
    }
    return report


async def analyze(src: str, job_dir: Path, run_decoder: bool = True, timeout: int = 300) -> dict[str, Any]:
    report = static_report(src)
    (job_dir / "keysystem_static.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    result: dict[str, Any] = {"static": report, "decoder": None}
    tool = settings.data_dir / "flowauth" / "flowauth_deobf.py"
    if run_decoder and report["luraph_payload"]:
        if not tool.is_file():
            result["decoder"] = {"ok": False, "error": f"{tool} not found (DATA_DIR/flowauth)"}
        else:
            out_dir = job_dir / "flowauth_out"
            out_dir.mkdir(exist_ok=True)
            payload = job_dir / "input.lua"
            runs = {}
            for cmd_name, args in (("info", ["info", str(payload)]),
                                   ("outer", ["outer", str(payload), "--out-dir", str(out_dir)])):
                cmd = [settings.python_bin, str(tool), *args]
                action("keysystem_decoder", command=cmd)
                try:
                    rc, so, se = await _run_process(cmd, cwd=tool.parent, env=None, timeout=timeout)
                    runs[cmd_name] = {"returncode": rc, "stdout": so[-6000:], "stderr": se[-3000:]}
                except TimeoutError as exc:
                    runs[cmd_name] = {"returncode": None, "error": str(exc)}
            produced = sorted(p.name for p in out_dir.iterdir()) if out_dir.is_dir() else []
            result["decoder"] = {"ok": all(r.get("returncode") == 0 for r in runs.values()), "runs": runs,
                                 "output_dir": str(out_dir), "files": produced}
    result["guidance"] = [
        "The stage-1 loader is plain or lightly obfuscated Lua: run deobfuscate on it to read what it does "
        "before the hand-off (transports, telemetry, integrity check).",
        "The protected payload (LPH/Luraph body) can be lifted with the luraph15 / luraph151 backends, but "
        "feature code that needs the server-signed start proof stays encrypted - that is the vendor's control "
        "working as designed (see Data/flowauth/DEOBFUSCATOR.md).",
        "For your own scripts, run them through the normal loader with your own key and analyse the result.",
    ]
    return result
