from __future__ import annotations

import math
import re
from collections import Counter


def mask_lua(source: str) -> tuple[str, str | None]:
    text = str(source or "")
    out: list[str] = []
    i, n = 0, len(text)
    unterminated = None

    def long_bracket_at(index: int):
        if index >= n or text[index] != "[":
            return None
        j = index + 1
        while j < n and text[j] == "=":
            j += 1
        if j < n and text[j] == "[":
            return j - index - 1
        return None

    while i < n:
        ch = text[i]
        if ch == "-" and i + 1 < n and text[i + 1] == "-":
            eqs = long_bracket_at(i + 2)
            if eqs is not None:
                close = "]" + "=" * eqs + "]"
                end = text.find(close, i + 3 + eqs)
                if end == -1:
                    unterminated = "long comment"
                    break
                out.extend("\n" if c == "\n" else " " for c in text[i:end + len(close)])
                i = end + len(close)
                continue
            end = text.find("\n", i + 2)
            if end == -1:
                out.extend(" " for _ in text[i:])
                break
            out.extend(" " for _ in text[i:end])
            out.append("\n")
            i = end + 1
            continue
        if ch in ("'", '"'):
            quote = ch
            out.append(" ")
            i += 1
            escaped = closed = False
            while i < n:
                c = text[i]
                out.append("\n" if c == "\n" else " ")
                i += 1
                if escaped:
                    escaped = False
                    continue
                if c == "\\":
                    escaped = True
                    continue
                if c == quote:
                    closed = True
                    break
            if not closed:
                unterminated = "string"
                break
            continue
        eqs = long_bracket_at(i)
        if eqs is not None:
            close = "]" + "=" * eqs + "]"
            end = text.find(close, i + 2 + eqs)
            if end == -1:
                unterminated = "long string"
                break
            out.extend("\n" if c == "\n" else " " for c in text[i:end + len(close)])
            i = end + len(close)
            continue
        out.append(ch)
        i += 1
    return "".join(out), unterminated


def validate_output(result: str) -> list[str]:
    problems: list[str] = []
    if not isinstance(result, str) or not result.strip():
        return ["empty output"]
    masked, unterminated = mask_lua(result)
    if unterminated:
        problems.append(f"unterminated {unterminated}")
        return problems
    if not re.sub(r"[\s;]+", "", masked):
        return ["no Lua code outside comments"]
    pairs = {")": "(", "]": "[", "}": "{"}
    stack: list[str] = []
    for ch in masked:
        if ch in "([{":
            stack.append(ch)
        elif ch in ")]}":
            if not stack or stack[-1] != pairs[ch]:
                problems.append(f"unexpected `{ch}`")
                break
            stack.pop()
    else:
        if stack:
            problems.append("unclosed bracket/parenthesis/table")
    tokens = re.findall(r"\b(?:function|if|for|while|do|repeat|end|until)\b", masked)
    blocks: list[str] = []
    pending_do = 0
    bad = None
    for t in tokens:
        if t in ("function", "if", "repeat"):
            blocks.append(t)
        elif t in ("for", "while"):
            blocks.append(t)
            pending_do += 1
        elif t == "do":
            if pending_do:
                pending_do -= 1
            else:
                blocks.append("do")
        elif t == "until":
            if not blocks or blocks[-1] != "repeat":
                bad = "unmatched `until`"
                break
            blocks.pop()
        elif t == "end":
            if not blocks or blocks[-1] == "repeat":
                bad = "unmatched `end`"
                break
            blocks.pop()
    if bad:
        problems.append(bad)
    elif blocks or pending_do:
        problems.append("unclosed Lua block(s)")
    lua_like = any((
        re.search(r"\b(?:local|function|return|if|for|while|repeat|do|break|continue)\b", masked),
        re.search(r"\b[A-Za-z_]\w*\s*=", masked),
        re.search(r"\b[A-Za-z_]\w*(?:\.[A-Za-z_]\w*|:[A-Za-z_]\w*)*\s*\(", masked),
    ))
    if not lua_like:
        problems.append("does not look like executable Lua")
    return problems


_LITERALS = [
    "--ironbrew3", "ironbrew3", "ironbrew", "aztupbrew", "luaobfuscator", "luraph", "lph_", "lph@", "lph+",
    "moonsec", "moonveil", "prometheus", "goofyscator", "goofyfuscator", "wynfuscate", "clyde", "jnkie",
    "getfenv", "setfenv", "loadstring", "string.char", "string.byte", "string.sub", "bit32", "bit.bxor",
    "coroutine.wrap", "coroutine.create", "table.concat", "math.floor", "return(function", "while true do",
    "select('#'", 'select("#"', "setmetatable", "game:httpget", "httpget(", "script_key", "flowauth",
    "pandadevelopment", "_bsdata0", "unpack(", "table.unpack", "newproxy", "debug.getinfo", "debug.info",
]


def features(src: str) -> list[str]:
    s = src.lower()
    f: set[str] = set()
    for lit in _LITERALS:
        if lit in s:
            f.add("lit:" + lit)
    if re.search(r'["\'][0-9a-f]{512,}["\']', src, re.I):
        f.add("shape:large_hex_string")
    if re.search(r'[A-Za-z0-9+/=]{2000,}', src):
        f.add("shape:large_base64_blob")
    if re.search(r'\[=*\[[^\]]{4000,}', src):
        f.add("shape:large_long_string")
    if len(re.findall(r"\bfunction\b", src)) > 50:
        f.add("shape:many_functions")
    if len(re.findall(r"\bwhile\b|\brepeat\b", src)) > 20:
        f.add("shape:many_loops")
    if len(re.findall(r"\bbit32\b|\bbit\.", src)) > 5:
        f.add("shape:bit_heavy")
    if len(re.findall(r"\[[^\]]+\]\s*=", src)) > 50:
        f.add("shape:table_dispatch")
    if "return(function" in s and "string.byte" in s and "math.floor" in s:
        f.add("shape:lua_vm_wrapper")
    if len(re.findall(r"\\\d{1,3}", src)) > 200:
        f.add("shape:escaped_strings")
    if re.search(r"\b[lI]{6,}\b", src) or len(re.findall(r"\b_0x[0-9a-fA-F]+\b", src)) > 20:
        f.add("shape:mangled_names")
    lines = src.count("\n") + 1
    if len(src) / max(lines, 1) > 1000:
        f.add("shape:minified")
    if re.search(r"loadstring\s*\(\s*game\s*:\s*HttpGet", src, re.I) and len(src) < 4000:
        f.add("shape:loader_stub")
    if len(src) > 200_000:
        f.add("size:large")
    return sorted(f)


def jaccard(a, b) -> float:
    a, b = set(a), set(b)
    return len(a & b) / len(a | b) if a and b else 0.0


_KNOWN_API = re.compile(
    r"\b(?:game|workspace|script|Instance\.new|GetService|Players|LocalPlayer|Character|Humanoid|"
    r"TweenService|RunService|UserInputService|ReplicatedStorage|print|warn|pairs|ipairs|"
    r"Connect|FindFirstChild|WaitForChild|Vector3|CFrame|Color3|UDim2|Enum|task\.\w+|wait|spawn)\b")
_OBF_MARKERS = ("luraph", "lph_", "ironbrew", "moonsec", "prometheus", "goofyscator", "luaobfuscator",
                "wynfuscate", "aztupbrew")


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    n = len(s)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def readability(src: str) -> dict:
    if not src or not src.strip():
        return {"score": 0.0, "verdict": "empty", "still_obfuscated": True, "reasons": ["empty"]}
    masked, _ = mask_lua(src)
    lines = src.splitlines() or [src]
    n_lines = len(lines)
    avg_len = sum(len(line) for line in lines) / n_lines
    max_len = max(len(line) for line in lines)
    idents = re.findall(r"\b[A-Za-z_]\w*\b", masked)
    keywords = {"local", "function", "end", "if", "then", "else", "elseif", "for", "in", "do", "while",
                "repeat", "until", "return", "and", "or", "not", "nil", "true", "false", "break", "continue"}
    names = [i for i in idents if i not in keywords]
    uniq = set(names)
    mangled = [n for n in uniq if re.fullmatch(r"[lI1_]{4,}|_0x[0-9a-fA-F]+|[a-zA-Z]_?\d{2,}|[A-Za-z]{1,2}", n)]
    mangled_ratio = len(mangled) / max(len(uniq), 1)
    escapes = len(re.findall(r"\\\d{1,3}|\\x[0-9a-fA-F]{2}", src))
    escape_density = escapes / max(len(src), 1) * 1000
    api_hits = len(_KNOWN_API.findall(masked))
    blob = max((len(m) for m in re.findall(r"[A-Za-z0-9+/=]{200,}", src)), default=0)
    lower = src.lower()
    markers = [m for m in _OBF_MARKERS if m in lower]
    vm_like = ("shape:lua_vm_wrapper" in features(src[:200_000])) or bool(
        re.search(r"while\s+true\s+do\s+local\s+\w+\s*=\s*\w+\[\w+\]", masked))
    ent = _entropy(src[:100_000])

    score = 100.0
    reasons: list[str] = []
    if avg_len > 200:
        score -= min(30, (avg_len - 200) / 40)
        reasons.append(f"very long lines (avg {avg_len:.0f} chars) - minified or packed")
    if max_len > 5000:
        score -= 10
        reasons.append(f"a line of {max_len} chars")
    if mangled_ratio > 0.4:
        score -= min(25, mangled_ratio * 30)
        reasons.append(f"{mangled_ratio:.0%} of identifiers look mangled (e.g. {', '.join(sorted(mangled)[:5])})")
    if escape_density > 5:
        score -= min(20, escape_density)
        reasons.append(f"{escapes} escaped bytes in strings - strings still encoded")
    if blob > 2000:
        score -= 20
        reasons.append(f"encoded blob of {blob} chars (packed payload / bytecode)")
    if markers:
        score -= 10
        reasons.append("obfuscator markers present: " + ", ".join(markers))
    if vm_like:
        score -= 25
        reasons.append("VM interpreter shape (dispatch loop / bytecode wrapper)")
    if ent > 5.6:
        score -= 10
        reasons.append(f"high character entropy ({ent:.2f})")
    if api_hits == 0 and len(src) > 500:
        score -= 10
        reasons.append("no recognisable Roblox/Lua API names in code")
    elif api_hits > 5:
        score += min(10, api_hits / 5)
    problems = validate_output(src)
    if problems:
        score -= 10
        reasons.append("structure: " + "; ".join(problems))
    if vm_like and markers:
        score = min(score, 35.0)
    elif vm_like or blob > 20_000:
        score = min(score, 50.0)
    score = max(0.0, min(100.0, score))
    verdict = "readable" if score >= 70 else "partially readable" if score >= 45 else "obfuscated"
    return {
        "score": round(score, 1), "verdict": verdict, "still_obfuscated": score < 70,
        "reasons": reasons or ["looks like normal source"],
        "metrics": {"lines": n_lines, "avg_line_len": round(avg_len, 1), "max_line_len": max_len,
                    "mangled_ratio": round(mangled_ratio, 2), "escape_count": escapes,
                    "api_hits": api_hits, "largest_blob": blob, "entropy": round(ent, 2)},
    }


_STR_RE = re.compile(r'"((?:[^"\\\n]|\\.)*)"|\'((?:[^\'\\\n]|\\.)*)\'')


def _decode_lua_escapes(body: str, quote: str) -> str | None:
    out: list[str] = []
    pending = bytearray()

    def flush() -> bool:
        if not pending:
            return True
        try:
            text = pending.decode("utf-8")
        except UnicodeDecodeError:
            return False
        for ch in text:
            if ch == "\\":
                out.append("\\\\")
            elif ch == quote:
                out.append("\\" + quote)
            elif ch in "\n\t\r":
                out.append({"\n": "\\n", "\t": "\\t", "\r": "\\r"}[ch])
            elif ord(ch) < 32 or ord(ch) == 127:
                return False
            else:
                out.append(ch)
        pending.clear()
        return True

    i = 0
    while i < len(body):
        c = body[i]
        if c == "\\" and i + 1 < len(body):
            m = re.match(r"\d{1,3}", body[i + 1:])
            if m:
                v = int(m.group(0))
                if v > 255:
                    return None
                pending.append(v)
                i += 1 + len(m.group(0))
                continue
            if body[i + 1] == "x" and re.fullmatch(r"[0-9a-fA-F]{2}", body[i + 2:i + 4]):
                pending.append(int(body[i + 2:i + 4], 16))
                i += 4
                continue
            if not flush():
                return None
            out.append(body[i:i + 2])
            i += 2
            continue
        if not flush():
            return None
        out.append(c)
        i += 1
    if not flush():
        return None
    return "".join(out)


def decode_string_escapes(src: str) -> tuple[str, int]:
    count = 0

    def repl(m):
        nonlocal count
        dq = m.group(1) is not None
        body = m.group(1) if dq else m.group(2)
        if not re.search(r"\\(\d|x[0-9a-fA-F])", body):
            return m.group(0)
        q = '"' if dq else "'"
        dec = _decode_lua_escapes(body, q)
        if dec is None:
            return m.group(0)
        count += 1
        return q + dec + q

    return _STR_RE.sub(repl, src), count


def fold_string_char(src: str) -> tuple[str, int]:
    count = 0

    def repl(m):
        nonlocal count
        try:
            nums = [int(x.strip(), 0) for x in m.group(1).split(",") if x.strip()]
        except ValueError:
            return m.group(0)
        if not nums or any(n < 0 or n > 255 for n in nums):
            return m.group(0)
        s = "".join(chr(n) for n in nums)
        if not all(32 <= ord(c) < 127 or c in "\n\t" for c in s):
            return m.group(0)
        count += 1
        return '"' + s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\t", "\\t") + '"'

    out = re.sub(r"\bstring\.char\s*\(\s*((?:0x[0-9a-fA-F]+|\d+)(?:\s*,\s*(?:0x[0-9a-fA-F]+|\d+))*)\s*\)",
                 repl, src)
    return out, count


def fold_concat(src: str) -> tuple[str, int]:
    count = 0
    pat = re.compile(r'"((?:[^"\\\n]|\\.)*)"\s*\.\.\s*"((?:[^"\\\n]|\\.)*)"')
    while True:
        new, n = pat.subn(lambda m: '"' + m.group(1) + m.group(2) + '"', src)
        if n == 0 or new == src:
            return src, count
        count += n
        src = new


def reindent(src: str, indent: str = "    ") -> str:
    masked, unterminated = mask_lua(src)
    if unterminated:
        return src
    src_lines = src.split("\n")
    m_lines = masked.split("\n")
    if len(src_lines) != len(m_lines):
        return src
    depth = 0
    out = []
    opens = re.compile(r"\b(function|then|do|repeat)\b|[({]")
    closes = re.compile(r"\b(end|until|elseif)\b|[)}]")
    for raw, m in zip(src_lines, m_lines):
        code = m.strip()
        stripped = raw.strip()
        if not stripped:
            out.append("")
            continue
        n_open = len(opens.findall(code))
        n_close = len(closes.findall(code))
        lead_close = re.match(r"^(end|until|else|elseif|[)}])", code)
        cur = depth - (1 if lead_close else 0)
        out.append(indent * max(cur, 0) + stripped)
        depth = max(0, depth + n_open - n_close)
    return "\n".join(out)


def pretty_print(src: str, mode: str = "auto") -> tuple[str, str]:
    lines = src.splitlines() or [src]
    minified = sum(len(x) for x in lines) / len(lines) > 200
    use_parser = mode == "luaparser" or (mode == "auto" and minified)
    if use_parser and len(src) < 1_500_000:
        try:
            from luaparser import ast
            tree = ast.parse(src)
            return ast.to_lua_source(tree), "luaparser"
        except Exception:
            pass
    return reindent(src), "reindent"


def cleanup(src: str, *, pretty: bool = True, formatter: str = "auto") -> tuple[str, dict]:
    stats: dict = {}
    base_ok = not validate_output(src)
    out = src
    for name, fn in (("string_char_folded", fold_string_char),
                     ("escaped_strings_decoded", decode_string_escapes),
                     ("concats_folded", fold_concat)):
        new, n = fn(out)
        if n and base_ok and validate_output(new):
            stats[name] = f"reverted ({n} edits broke structure)"
            continue
        stats[name] = n
        out = new
    if pretty:
        formatted, how = pretty_print(out, formatter)
        if formatted.strip() and not validate_output(formatted):
            out = formatted
            stats["formatter"] = how
        else:
            stats["formatter"] = "skipped (formatter output failed validation)"
    return out, stats
