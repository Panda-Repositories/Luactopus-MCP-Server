from __future__ import annotations

import json
import re
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import backends, storage
from .config import settings
from .detect import detect
from .logs import action
from .luatext import cleanup, features, readability, validate_output

JOB_RE = re.compile(r"^[A-Za-z0-9_-]{6,40}$")


def new_job(source: str, label: str = "") -> tuple[str, Path]:
    job_id = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6]
    d = settings.jobs_dir / job_id
    d.mkdir(parents=True, exist_ok=True)
    (d / "input.lua").write_text(source, encoding="utf-8", errors="replace")
    meta = {"job_id": job_id, "label": label, "created": datetime.now(timezone.utc).isoformat(),
            "input_chars": len(source)}
    (d / "job.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    action("job_created", job_id=job_id, label=label, input_chars=len(source))
    return job_id, d


def job_dir(job_id: str) -> Path:
    if not JOB_RE.match(job_id or ""):
        raise ValueError("invalid job id")
    d = (settings.jobs_dir / job_id).resolve()
    if not d.is_dir() or settings.jobs_dir.resolve() not in d.parents:
        raise FileNotFoundError(f"job {job_id} not found")
    return d


def job_file(job_id: str, name: str) -> Path:
    d = job_dir(job_id)
    p = (d / name).resolve()
    if d not in p.parents and p != d:
        raise PermissionError("path escapes the job folder")
    if not p.is_file():
        raise FileNotFoundError(f"{name} not found in job {job_id}")
    return p


def list_jobs(limit: int = 30) -> list[dict[str, Any]]:
    if not settings.jobs_dir.is_dir():
        return []
    out = []
    for d in sorted(settings.jobs_dir.iterdir(), reverse=True)[:limit]:
        if not d.is_dir():
            continue
        info: dict[str, Any] = {"job_id": d.name}
        rp = d / "report.json"
        if rp.is_file():
            try:
                r = json.loads(rp.read_text(encoding="utf-8"))
                info.update({"status": r.get("status"), "final_readability": r.get("final_readability", {}).get("score"),
                             "layers": [l.get("accepted_backend") for l in r.get("layers", [])]})
            except Exception:
                pass
        out.append(info)
    return out


def preview(text: str, lines: int = 60, max_chars: int = 6000) -> str:
    chunk = "\n".join(text.splitlines()[:lines])
    if len(chunk) > max_chars:
        chunk = chunk[:max_chars] + "\n-- ... (truncated)"
    return chunk


async def run_one(job_id: str, layer: int, backend_id: str, source: str, *, timeout: int | None,
                  use_override: bool, options: dict[str, Any] | None, detected: str | None = None
                  ) -> tuple[backends.RunResult, dict[str, Any]]:
    d = job_dir(job_id)
    run_dir = d / f"layer{layer}_{backend_id.replace(':', '_')}"
    n = 2
    while run_dir.exists():
        run_dir = d / f"layer{layer}_{backend_id.replace(':', '_')}_{n}"
        n += 1
    res = await backends.run_backend(backend_id, source, run_dir, timeout=timeout, use_override=use_override,
                                     options=options, job_id=job_id)
    problems = validate_output(res.output) if res.ok else []
    score = readability(res.output) if res.ok else None
    info = {**res.summary(), "validation_problems": problems,
            "readability": score, "changed": res.ok and res.output.strip() != source.strip()}
    if res.ok:
        (run_dir / "output.lua").write_text(res.output, encoding="utf-8")
        if "RECOVERY STATUS: INCOMPLETE" in res.output[:3000]:
            info["hint"] = ("backend could not trace the script - it needs a Lua 5.3/5.4 (LUA_BIN) or Lune "
                            "(LUNE_BIN) runtime; see server_status")
    try:
        storage.record_run(job_id=job_id, layer=layer, backend=backend_id, detected=detected,
                           features=features(source[:400_000]), ok=bool(res.ok and not problems and info["changed"]),
                           readability=score["score"] if score else None, seconds=res.seconds, error=res.error,
                           override=res.override)
    except Exception:
        pass
    return res, info


async def deobfuscate(source: str, *, backend: str = "auto", max_layers: int | None = None,
                      tries_per_layer: int = 3, timeout: int | None = None, use_overrides: bool = True,
                      do_cleanup: bool = True, formatter: str = "auto", options: dict[str, Any] | None = None,
                      label: str = "", target_score: float = 70.0) -> dict[str, Any]:
    started = time.perf_counter()
    job_id, d = new_job(source, label)
    max_layers = max(1, min(max_layers or settings.max_layers, 12))
    current = source
    layers: list[dict[str, Any]] = []
    status = "unchanged"
    first = readability(source)
    tried_global: set[tuple[int, str]] = set()
    det0 = detect(source)

    for layer in range(1, max_layers + 1):
        score_now = readability(current)
        det = det0 if layer == 1 else detect(current)
        if layer > 1 and score_now["score"] >= target_score and not det.key_system:
            break
        if backend != "auto" and layer == 1:
            order = [backend]
        else:
            order = [c.backend for c in det.candidates]
            if layer > 1 and all(c.backend in ("envtrace", "oxygen") for c in det.candidates):
                if score_now["score"] >= 45:
                    break
        available = [b for b in order if b in backends.BACKENDS or b.startswith("custom:")]
        layer_info: dict[str, Any] = {"layer": layer, "detection": det.to_dict(), "readability_before": score_now,
                                      "attempts": []}
        accepted = None
        for bk in available[:max(1, tries_per_layer)]:
            if (layer, bk) in tried_global:
                continue
            tried_global.add((layer, bk))
            try:
                b = backends.get(bk)
            except KeyError:
                continue
            if b.missing(use_overrides):
                layer_info["attempts"].append({"backend": bk, "ok": False, "skipped": True,
                                               "error": "unavailable: " + "; ".join(b.missing(use_overrides))})
                continue
            res, info = await run_one(job_id, layer, bk, current, timeout=timeout, use_override=use_overrides,
                                      options=options, detected=det.best.family if det.best else None)
            layer_info["attempts"].append(info)
            if not res.ok or not info["changed"]:
                continue
            new_score = info["readability"]["score"]
            if info["validation_problems"] and new_score < score_now["score"] + 10:
                info["rejected"] = "output failed structure validation without a clear readability gain"
                continue
            if new_score < score_now["score"] + 3 and not _family_gone(det, res.output):
                info["rejected"] = (f"no improvement (readability {score_now['score']} -> {new_score}) and the "
                                    "obfuscator is still detected")
                continue
            accepted = (bk, res.output, info)
            break
        if not accepted:
            layer_info["accepted_backend"] = None
            layers.append(layer_info)
            if layer == 1:
                status = "failed"
            break
        bk, out, info = accepted
        layer_info["accepted_backend"] = bk
        layer_info["readability_after"] = info["readability"]
        (d / f"layer{layer}.lua").write_text(out, encoding="utf-8")
        layers.append(layer_info)
        current = out
        status = "deobfuscated"
        if info["readability"]["score"] >= target_score:
            if not detect(current).candidates or all(c.confidence < .8 for c in detect(current).candidates):
                break

    cleanup_stats = None
    if do_cleanup and status != "failed":
        cleaned, cleanup_stats = cleanup(current, formatter=formatter)
        if cleaned != current:
            current = cleaned
            if status == "unchanged":
                status = "cleaned"
    final_score = readability(current)
    (d / "final.lua").write_text(current, encoding="utf-8")

    next_steps: list[str] = []
    if status == "failed":
        tried = [a["backend"] for l in layers for a in l["attempts"]]
        next_steps += [
            f"All tried backends failed ({', '.join(tried) or 'none available'}). Inspect stderr in the job folder "
            "with read_job_file, or run_backend with another backend id (list_backends).",
            "If a backend crashed on a format variant, use list_tool_files/read_tool_file to find the failing code, "
            "fork_tool + edit_tool_file to patch it, then rerun with use_overrides=true.",
        ]
    next_steps += sorted({a["hint"] for l in layers for a in l["attempts"] if a.get("hint")})
    if final_score["still_obfuscated"]:
        next_steps.append("Output is still not fully readable: " + "; ".join(final_score["reasons"][:4]) +
                          ". Try another layer (deobfuscate on the job's final.lua), cleanup_lua, or a custom tool.")
    if det0.key_system:
        next_steps.append("Key-system loader detected: use analyze_key_system for offline structure analysis.")
    if det0.loader_stub:
        next_steps.append("Input is a loader stub; deobfuscate the downloaded script instead.")
    elif status != "failed" and "shape:loader_stub" in features(current):
        urls = re.findall(r"https?://[^\s\"')]+", current)[:5]
        next_steps.append("The deobfuscated result is a loader stub that downloads the real script at runtime"
                          + (f" ({', '.join(urls)})" if urls else "") +
                          ". Fetch that URL's content and run deobfuscate on it for the next stage.")

    report = {
        "job_id": job_id, "status": status, "job_dir": str(d), "final_path": str(d / "final.lua"),
        "seconds": round(time.perf_counter() - started, 2), "initial_readability": first,
        "final_readability": final_score, "layers": layers, "cleanup": cleanup_stats,
        "key_system": det0.key_system, "next_steps": next_steps,
    }
    (d / "report.json").write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    action("job_done", job_id=job_id, status=status, final_score=final_score["score"],
           layers=[l.get("accepted_backend") for l in layers])
    return {**{k: v for k, v in report.items() if k != "layers"},
            "layers": [_slim_layer(l) for l in layers],
            "final_preview": preview(current)}


def _family_gone(det_before, output: str) -> bool:
    if not det_before.best:
        return True
    fam = det_before.best.family
    after = detect(output[:2_000_000])
    return not any(c.family == fam and c.confidence >= .8 for c in after.candidates)


def _slim_layer(l: dict[str, Any]) -> dict[str, Any]:
    return {
        "layer": l["layer"], "accepted_backend": l.get("accepted_backend"),
        "detected": (l["detection"].get("best") or {}).get("family"),
        "candidates": [(c["backend"], c["confidence"]) for c in l["detection"]["candidates"][:5]],
        "readability_before": l["readability_before"]["score"],
        "readability_after": (l.get("readability_after") or {}).get("score"),
        "attempts": [{"backend": a.get("backend"), "ok": a.get("ok"), "error": (a.get("error") or "")[:600] or None,
                      "skipped": a.get("skipped", False), "rejected": a.get("rejected"), "hint": a.get("hint"),
                      "readability": (a.get("readability") or {}).get("score"),
                      "validation_problems": a.get("validation_problems")} for a in l["attempts"]],
    }
