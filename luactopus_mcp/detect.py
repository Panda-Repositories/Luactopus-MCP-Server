from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from typing import Any

from . import storage
from .config import settings
from .luatext import features, jaccard


@dataclass
class Candidate:
    backend: str
    family: str
    confidence: float
    reason: str


@dataclass
class Detection:
    candidates: list[Candidate]
    features: list[str]
    key_system: dict[str, Any] | None = None
    loader_stub: bool = False
    notes: list[str] = field(default_factory=list)

    @property
    def best(self) -> Candidate | None:
        return self.candidates[0] if self.candidates else None

    def to_dict(self) -> dict[str, Any]:
        return {"best": asdict(self.best) if self.best else None,
                "candidates": [asdict(c) for c in self.candidates], "features": self.features,
                "key_system": self.key_system, "loader_stub": self.loader_stub, "notes": self.notes}


FAMILY_BACKENDS = {
    "prometheus": ["prometheus"],
    "clyde": ["clyde"],
    "goofyscator": ["goofyscator_v10", "goofyscator"],
    "luaobfuscator": ["luaobfuscator"],
    "ironbrew1": ["ib1"],
    "ironbrew2": ["ib2", "luaobfuscator"],
    "ironbrew3": ["ib3"],
    "luraph": ["luraph15", "luraph149", "luraph148", "luraph147", "luraph151"],
}

_TERROR_MAP = {"ironbrew3": "ironbrew3", "ib3": "ironbrew3", "ironbrew2": "ironbrew2", "aztup": "ironbrew2",
               "ib2": "ironbrew2", "ironbrew1": "ironbrew1", "ib1": "ironbrew1", "luaobfuscator": "luaobfuscator",
               "luraph": "luraph", "prometheus": "prometheus", "goofy": "goofyscator", "clyde": "clyde"}


def _rules(src: str) -> list[Candidate]:
    s = src.lower()
    head = src.lstrip()[:400]
    out: list[Candidate] = []

    def add(backend, family, conf, reason):
        out.append(Candidate(backend, family, conf, reason))

    if "goofyscator" in s or "goofyfuscator" in s:
        add("goofyscator_v10", "goofyscator", .97, "marker 'goofyscator'")
        add("goofyscator", "goofyscator", .95, "marker 'goofyscator' (V11 recovery)")
    if "--ironbrew3" in s or "ironbrew3:" in s:
        add("ib3", "ironbrew3", .99, "marker 'ironbrew3'")
    if "aztupbrew" in s:
        add("ib2", "ironbrew2", .99, "marker 'aztupbrew'")
    elif "ironbrew" in s and "ironbrew3" not in s:
        add("ib2", "ironbrew2", .85, "marker 'ironbrew'")
        add("ib1", "ironbrew1", .6, "marker 'ironbrew' (could be IB1)")
    if "luaobfuscator" in s:
        add("luaobfuscator", "luaobfuscator", .95, "marker 'luaobfuscator'")
    if "prometheus" in s:
        add("prometheus", "prometheus", .9, "marker 'prometheus'")
    if "wearedevs.net/obfuscator" in s:
        add("prometheus", "prometheus", .93, "WeAreDevs obfuscator banner (Prometheus fork)")
    if "clyde" in s:
        add("clyde", "clyde", .8, "marker 'clyde'")
    if "wynfuscate" in s:
        add("envtrace", "wynfuscate", .4, "wYnFuscate has no dedicated backend - behaviour trace")
    if "moonsec" in s:
        add("envtrace", "moonsec", .4, "MoonSec has no dedicated backend - behaviour trace")
    if "luraph" in s or "lph_" in s or re.search(r"\[=+\[LPH.", src):
        version = None
        for v, needle in (("149", "14.9"), ("148", "14.8"), ("147", "14.7")):
            if f"v{needle}" in s or needle in s:
                version = v
                break
        if version:
            add(f"luraph{version}", "luraph", .99, f"Luraph banner v{version[:2]}.{version[2]}")
        elif "v15" in s or "luraph obfuscator v15" in s:
            add("luraph15", "luraph", .97, "Luraph v15 banner")
            add("luraph151", "luraph", .8, "Luraph v15.x (external devirtualizer)")
        else:
            add("luraph15", "luraph", .7, "Luraph marker, version unknown")
            add("luraph151", "luraph", .6, "Luraph marker (external v15.1 devirtualizer)")
            add("luraph149", "luraph", .5, "Luraph marker - try v14.9")
            add("luraph148", "luraph", .45, "Luraph marker - try v14.8")
            add("luraph147", "luraph", .4, "Luraph marker - try v14.7")
    if head.startswith("local init = (function(...") and "return({" in head:
        add("luraph148", "luraph", .8, "Luraph v14.8 layout (local init = (function(...)")
    if "string.byte" in s and "return(function" in s and "math.floor" in s:
        add("ib1", "ironbrew1", .55, "IB1-style VM wrapper shape")
    return out


def _fingerprint_candidates(feats: list[str]) -> list[Candidate]:
    out: list[Candidate] = []
    fp_file = settings.tools_dir / "deobfuscators" / "fingerprints" / "terrorlua.json"
    db: dict[str, Any] = {}
    if fp_file.is_file():
        try:
            db = json.loads(fp_file.read_text(encoding="utf-8"))
        except Exception:
            db = {}
    for folder, item in db.items():
        sc = jaccard(feats, item.get("features", []))
        if sc < .18:
            continue
        fam = next((v for k, v in _TERROR_MAP.items() if k in folder.lower()), None)
        if fam and fam in FAMILY_BACKENDS:
            for i, bk in enumerate(FAMILY_BACKENDS[fam][:2]):
                out.append(Candidate(bk, fam, round(min(.9, max(.35, sc)) - i * .05, 3),
                                     f"bot fingerprint '{folder}' (jaccard {sc:.2f})"))
    try:
        learned = storage.fingerprints()
    except Exception:
        learned = []
    for fp in learned:
        sc = jaccard(feats, fp["features"])
        if sc < .5:
            continue
        backends = [fp["backend"]] if fp.get("backend") else FAMILY_BACKENDS.get(fp["family"], [])
        for bk in backends:
            out.append(Candidate(bk, fp["family"], round(min(.96, .5 + sc * .45), 3),
                                 f"taught fingerprint #{fp['id']} '{fp['family']}' (jaccard {sc:.2f})"))
    return out


def _history_candidates(feats: list[str]) -> list[Candidate]:
    try:
        runs = storage.run_history(1500)
    except Exception:
        return []
    score: dict[str, list[float]] = {}
    for r in runs:
        sim = jaccard(feats, r["features"])
        if sim < .6:
            continue
        s = score.setdefault(r["backend"], [0.0, 0.0])
        s[0] += sim * (1 if r["ok"] and (r["readability"] or 0) >= 45 else -0.6)
        s[1] += sim
    out = []
    for bk, (pos, tot) in score.items():
        if tot <= 0 or pos <= 0:
            continue
        conf = round(min(.93, .45 + .5 * pos / tot), 3)
        out.append(Candidate(bk, "learned", conf, f"worked before on similar inputs (score {pos:.1f}/{tot:.1f})"))
    return out


def key_system_info(src: str) -> dict[str, Any] | None:
    s = src.lower()
    hits: dict[str, list[str]] = {}

    def hit(name, why):
        hits.setdefault(name, []).append(why)

    if "flowauth" in s:
        hit("FlowAuth", "string 'flowauth'")
    if "_bsdata0" in src:
        hit("FlowAuth", "stage-1 handoff '_bsdata0'")
    if re.search(r"\[=*\[LPH[@+]", src) and ("launch_ticket" in s or "/v1/auth/" in s):
        hit("FlowAuth", "LPH payload + /v1/auth routes")
    if "pandadevelopment" in s or "panda auth" in s or "pandaauth" in s:
        hit("Panda Auth", "panda markers")
    if "luarmor" in s:
        hit("Luarmor", "string 'luarmor'")
    if "jnkie" in s:
        hit("jnkie", "string 'jnkie'")
    if "script_key" in s:
        hit("generic key system", "reads global 'script_key'")
    if not hits:
        return None
    urls = sorted(set(re.findall(r"https?://[^\s\"'<>\\)]+", src)))[:40]
    return {"systems": hits, "urls": urls,
            "note": "Key-system loader detected. Its protected payload is fetched at runtime and gated by the "
                    "vendor's server; use analyze_key_system for offline structure analysis. Luactopus does "
                    "not bypass licensing or key checks."}


def detect(src: str) -> Detection:
    feats = features(src)
    cands = _rules(src) + _fingerprint_candidates(feats) + _history_candidates(feats)
    merged: dict[str, Candidate] = {}
    for c in cands:
        cur = merged.get(c.backend)
        if cur is None:
            merged[c.backend] = c
        else:
            hi, lo = (cur, c) if cur.confidence >= c.confidence else (c, cur)
            merged[c.backend] = Candidate(c.backend, hi.family if hi.family != "learned" else lo.family,
                                          round(min(.995, hi.confidence + lo.confidence * .1), 3),
                                          hi.reason + "; " + lo.reason)
    ranked = sorted(merged.values(), key=lambda c: -c.confidence)
    notes: list[str] = []
    stub = "shape:loader_stub" in feats
    if stub:
        notes.append("This looks like a loader stub (loadstring(game:HttpGet(...))). The real script is "
                     "downloaded at runtime - fetch the URL's content and deobfuscate that instead.")
    if not ranked:
        notes.append("No known obfuscator matched. Falling back to the behaviour trace / env logger, or "
                     "the script may already be plain Lua (check readability).")
        ranked = [Candidate("envtrace", "unknown", .3, "fallback: generic behaviour trace"),
                  Candidate("oxygen", "unknown", .25, "fallback: Oxygen env logger")]
    return Detection(ranked, feats, key_system_info(src), stub, notes)
