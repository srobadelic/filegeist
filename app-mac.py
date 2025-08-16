#!/usr/bin/env python3
# =========================================
# App Name: Filegeist
# Maker/Developer: Steven Sroba
# Platform: macOS (Spotlight-backed files agent)
# =========================================

__app_name__ = "Filegeist"
__author__ = "Steven Sroba"
__version__ = "0.1.0"
import os, json, shlex, subprocess, base64
from flask import Flask, request, jsonify
from pathlib import Path

app = Flask(__name__)

# ---------- Config ----------
ALLOWLIST = [Path(p).expanduser().resolve() for p in os.getenv("FILES_ALLOWLIST", "~/Documents:~/Desktop").split(":")]
MAX_READ_BYTES = int(os.getenv("MAX_READ_BYTES", "200000"))  # ~200 KB
DEFAULT_SEARCH_ROOT = os.getenv("DEFAULT_SEARCH_ROOT", str(Path.home()))
REDACT = os.getenv("REDACT", "1") == "1"  # simple PII scrubber toggle

def in_allowlist(p: Path) -> bool:
    try:
        rp = p.expanduser().resolve()
    except Exception:
        return False
    return any(str(rp).startswith(str(root)) for root in ALLOWLIST)

def run(cmd: list[str]) -> tuple[int,str,str]:
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out, err = proc.communicate()
    return proc.returncode, out, err

def mdls(path: str) -> dict:
    rc, out, _ = run(["/usr/bin/mdls", "-name", "kMDItemDisplayName", "-name", "kMDItemContentType",
                      "-name", "kMDItemUserTags", "-name", "kMDItemContentTypeTree", path])
    meta = {"displayName": Path(path).name, "contentType": None, "tags": [], "utiTree": []}
    if rc == 0:
        lines = [l for l in out.splitlines() if "=" in l]
        parsed = {l.split("=")[0].strip(): "=".join(l.split("=")[1:]).strip() for l in lines}
        def clean(v): return v.strip().strip('"')
        meta["displayName"] = clean(parsed.get("kMDItemDisplayName", meta["displayName"]))
        ctype = parsed.get("kMDItemContentType")
        if ctype: meta["contentType"] = clean(ctype)
        tags = parsed.get("kMDItemUserTags")
        if tags and "(" in tags and ")" in tags:
            inside = tags[tags.index("(")+1:tags.rindex(")")]
            if inside.strip():
                meta["tags"] = [t.strip().strip('"') for t in inside.split(",")]
        utiTree = parsed.get("kMDItemContentTypeTree")
        if utiTree and "(" in utiTree and ")" in utiTree:
            inside = utiTree[utiTree.index("(")+1:utiTree.rindex(")")]
            if inside.strip():
                meta["utiTree"] = [t.strip().strip('"') for t in inside.split(",")]
    return meta

def redact_text(s: str) -> str:
    if not REDACT: return s
    import re
    s = re.sub(r'\b[\w\.-]+@[\w\.-]+\.\w+\b', '[redacted_email]', s)
    s = re.sub(r'\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b', '[redacted_ssn]', s)
    s = re.sub(r'\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b', '[redacted_phone]', s)
    return s

# ---------- Endpoints ----------
@app.get("/health")
def health():
    return jsonify({"ok": True, "allowlist": [str(p) for p in ALLOWLIST], "max_read_bytes": MAX_READ_BYTES})

@app.get("/search")
def search():
    """
    Query params:
      q       Spotlight query (e.g. 'budget', or a full query expression)
      folder  optional root (defaults to DEFAULT_SEARCH_ROOT)
      limit   int (default 50)
      raw     '1' => pass q straight to mdfind, else wrap as filename/content search
      exts    comma list of extensions to filter client-side
      tags    comma list of Finder tags to filter client-side
    """
    q = request.args.get("q", "").strip()
    if not q:
        return jsonify({"error": "missing q"}), 400
    folder = request.args.get("folder", DEFAULT_SEARCH_ROOT)
    try:
        folder = str(Path(folder).expanduser().resolve())
    except Exception:
        return jsonify({"error": "bad folder"}), 400
    if not in_allowlist(Path(folder)):
        return jsonify({"error": f"folder not in allowlist: {folder}"}), 403
    limit = int(request.args.get("limit", "50"))
    raw = request.args.get("raw", "0") == "1"
    exts = [e.lower().lstrip(".") for e in request.args.get("exts", "").split(",") if e]
    ftag = [t for t in request.args.get("tags", "").split(",") if t]

    if raw:
        mdquery = q
    else:
        # Basic: match in name OR indexed content
        # Escape quotes in q
        qq = q.replace('"', '\\"')
        mdquery = f'(kMDItemDisplayName == "*{qq}*"cd) || (kMDItemTextContent == "*{qq}*"cd)'

    cmd = ["/usr/bin/mdfind", "-0", "-onlyin", folder, mdquery]
    rc, out, err = run(cmd)
    if rc != 0:
        return jsonify({"error": "mdfind error", "stderr": err, "cmd": cmd}), 500

    paths = [p for p in out.split("\x00") if p]
    results = []
    for p in paths[: max(1, limit*2)]:  # overfetch a bit; we’ll filter below
        meta = mdls(p)
        if exts:
            ext = Path(p).suffix.lower().lstrip(".")
            if ext not in exts: continue
        if ftag:
            if not set(ftag).issubset(set(meta.get("tags", []))): continue
        results.append({"path": p, **meta})
        if len(results) >= limit: break
    return jsonify(results)

@app.post("/read")
def read():
    """
    JSON body: { "path": str, "max_bytes": int?, "mode": "text"|"bytes" }
    """
    data = request.get_json(force=True, silent=True) or {}
    path = data.get("path")
    if not path: return jsonify({"error": "missing path"}), 400
    p = Path(path)
    if not in_allowlist(p): return jsonify({"error": "path not in allowlist"}), 403
    if not p.exists() or not p.is_file(): return jsonify({"error": "not a file"}), 400

    maxb = int(data.get("max_bytes", MAX_READ_BYTES))
    mode = data.get("mode", "text")
    try:
        with open(p, "rb") as f:
            chunk = f.read(maxb)
    except Exception as e:
        return jsonify({"error": f"read failed: {e}"}), 500

    if mode == "bytes":
        return jsonify({"bytes_b64": base64.b64encode(chunk).decode("ascii"), "truncated": p.stat().st_size > maxb})
    else:
        try:
            text = chunk.decode("utf-8", errors="replace")
        except Exception:
            text = chunk.decode("latin-1", errors="replace")
        text = redact_text(text)
        return jsonify({"text": text, "truncated": p.stat().st_size > maxb})

@app.post("/open")
def open_in_finder():
    """
    JSON body: { "path": str, "reveal": bool? }
    """
    data = request.get_json(force=True, silent=True) or {}
    path = data.get("path")
    reveal = bool(data.get("reveal", True))
    if not path: return jsonify({"error": "missing path"}), 400
    p = Path(path)
    if not in_allowlist(p): return jsonify({"error": "path not in allowlist"}), 403
    if not p.exists(): return jsonify({"error": "not found"}), 404

    if reveal:
        # Reveal file in Finder
        script = f'tell application "Finder" to reveal POSIX file "{shlex.quote(str(p))}"'
        script2 = 'tell application "Finder" to activate'
        rc1, _, err1 = run(["/usr/bin/osascript", "-e", script])
        rc2, _, err2 = run(["/usr/bin/osascript", "-e", script2])
        ok = (rc1 == 0 and rc2 == 0)
        return jsonify({"ok": ok, "stderr": (err1 + err2 if not ok else "")}), (200 if ok else 500)
    else:
        # Open with default app
        rc, _, err = run(["/usr/bin/open", str(p)])
        return jsonify({"ok": rc == 0, "stderr": err}), (200 if rc == 0 else 500)

@app.post("/tag")
def set_tags():
    """
    JSON body: { "path": str, "tags": [str] }
    """
    data = request.get_json(force=True, silent=True) or {}
    path = data.get("path")
    tags = data.get("tags", [])
    if not path or not isinstance(tags, list): return jsonify({"error": "missing path/tags"}), 400
    p = Path(path)
    if not in_allowlist(p): return jsonify({"error": "path not in allowlist"}), 403
    if not p.exists(): return jsonify({"error": "not found"}), 404

    # Finder AppleScript supports tag names directly
    # Note: tag colors aren’t set here—only names.
    tag_list = ", ".join(f'"{t}"' for t in tags)
    script = f'''
    set theFile to POSIX file "{shlex.quote(str(p))}" as alias
    tell application "Finder"
      set tag names of theFile to {{{tag_list}}}
    end tell
    '''
    rc, _, err = run(["/usr/bin/osascript", "-e", script])
    return jsonify({"ok": rc == 0, "stderr": err}), (200 if rc == 0 else 500)

@app.get("/spotlight_raw")
def spotlight_raw():
    q = request.args.get("q", "").strip()
    folder = request.args.get("folder", DEFAULT_SEARCH_ROOT)
    try:
        folder = str(Path(folder).expanduser().resolve())
    except Exception:
        return jsonify({"error": "bad folder"}), 400
    if not in_allowlist(Path(folder)):
        return jsonify({"error": f"folder not in allowlist: {folder}"}), 403

    if not q: return jsonify({"error": "missing q"}), 400
    rc, out, err = run(["/usr/bin/mdfind", "-0", "-onlyin", folder, q])
    if rc != 0:
        return jsonify({"error": "mdfind error", "stderr": err}), 500
    return jsonify([p for p in out.split("\x00") if p])

if __name__ == "__main__":
    # Run: FLASK_RUN_PORT=27121 python3 app.py
    app.run(host="127.0.0.1", port=int(os.getenv("FLASK_RUN_PORT", "27121")))
