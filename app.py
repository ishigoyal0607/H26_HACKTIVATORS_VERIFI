"""
Dependency Exit Capsule Builder  (Hacktoberfest Hack Day, Track 1: Gemma 4)

What it does, in plain words:
  1. SCAN     - reads the target repo's requirements files and finds, with Python's own
                parser (ast), every place each package is imported.        -> OBSERVED
  2. ANALYZE  - gives those facts to a local Gemma 4 model (through Ollama) and asks for a
                risk opinion, a replacement and migration steps.            -> AI-GENERATED
  3. VERIFY   - builds clean virtual environments and really runs the repo's tests, first
                with the original dependency and then with a replacement.   -> OBSERVED
  4. EXPORT   - writes a Dependency Exit Capsule (Markdown + JSON) that keeps the AI's
                opinions and the observed evidence in separate sections.

Run with:  python -m streamlit run app.py
Nothing is sent to any cloud AI. Gemma runs on this laptop.
"""
import ast
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time
import urllib.request
from datetime import datetime
from pathlib import Path

import ollama
import streamlit as st

APP_DIR = Path(__file__).resolve().parent
WORK_DIR = APP_DIR / ".capsule_work"      # scratch space (add to .gitignore)
OUT_DIR = APP_DIR / "capsule_output"      # saved capsules
SKIP_DIRS = {".git", ".venv", "venv", "env", "__pycache__", "node_modules", ".tox",
             ".mypy_cache", ".pytest_cache", ".capsule_work", "capsule_output"}
DEFAULT_MODELS = ["gemma4:e2b", "gemma4:e4b", "gemma4:12b"]

# pip name -> import name(s), only where they differ from the pip name
IMPORT_NAMES = {
    "python-dateutil": ["dateutil"], "pyyaml": ["yaml"], "beautifulsoup4": ["bs4"],
    "pillow": ["PIL"], "scikit-learn": ["sklearn"], "opencv-python": ["cv2"],
    "python-dotenv": ["dotenv"], "pyjwt": ["jwt"], "attrs": ["attr", "attrs"],
    "setuptools": ["setuptools", "pkg_resources"], "msgpack-python": ["msgpack"],
}
# quick-fill only; the user can type anything: pip name, import name
PRESETS = {"appdirs": ("platformdirs", "platformdirs"), "toml": ("", "tomllib"),
           "Jinja2": ("Jinja2>=3.1,<4", "jinja2"), "pydantic": ("pydantic>=2,<3", "pydantic")}

LIMITATIONS = [
    "The import scan is static: dynamic imports, transitive use, and use outside Python files "
    "(templates, config) are not detected. 'Not imported directly' does NOT mean 'safe to remove'.",
    "Gemma is a small local model. Everything it writes is an unverified suggestion, not a fact.",
    "Test results only prove what the repository's existing tests cover.",
    "Replacement experiments apply a mechanical import rewrite. Any behaviour difference shows up "
    "only if a test exercises it, and some migrations need manual code changes.",
    "Only dependencies with an executed experiment are verified. All other replacements are suggestions.",
    "The heuristic risk level uses PyPI release dates when the PyPI lookup is enabled; otherwise it is not computed.",
    "Security vulnerabilities were deliberately not assessed (out of scope per the organizers).",
]


# ───────────────────────────── helpers ─────────────────────────────
def _rm(path):
    """Delete a folder, including read-only files (git objects on Windows)."""
    path = Path(path)
    if not path.exists():
        return

    def handler(func, p, _exc):
        try:
            os.chmod(p, stat.S_IWRITE)
            func(p)
        except Exception:
            pass
    try:
        shutil.rmtree(path, onexc=handler)
    except TypeError:
        shutil.rmtree(path, onerror=handler)


def run(cmd, cwd=None, timeout=900):
    """Run a command. Returns (return_code, combined_output, seconds)."""
    t0 = time.time()
    env = {**os.environ, "PYTHONUTF8": "1", "PIP_DISABLE_PIP_VERSION_CHECK": "1", "NO_COLOR": "1"}
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=timeout, env=env)
        return p.returncode, (p.stdout or "") + (p.stderr or ""), time.time() - t0
    except subprocess.TimeoutExpired:
        return -1, f"TIMEOUT after {timeout}s", time.time() - t0
    except FileNotFoundError as e:
        return -2, f"Command not found: {e}", time.time() - t0


def tail(text, n=3500):
    return text if len(text) <= n else "...\n" + text[-n:]


def venv_python(venv_dir):
    sub = "Scripts/python.exe" if os.name == "nt" else "bin/python"
    return str(Path(venv_dir) / sub)


def resolve_target(target):
    """Accept a local folder OR a GitHub URL (cloned into the scratch folder)."""
    target = target.strip().strip('"')
    if re.match(r"^https?://", target):
        name = target.rstrip("/").split("/")[-1]
        name = name[:-4] if name.endswith(".git") else name
        dest = WORK_DIR / "targets" / name
        _rm(dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        rc, out, _ = run(["git", "clone", "--depth", "1", target, str(dest)], timeout=300)
        if rc != 0:
            raise RuntimeError("git clone failed. Is Git installed and the URL correct?\n" + tail(out, 600))
        return dest
    p = Path(target)
    if not target or not p.exists():
        raise FileNotFoundError("That folder does not exist. Paste the full path, or a GitHub URL.")
    return p


def locate_requirements(repo):
    """Find the shallowest requirements.txt (zip files often nest the folder twice)."""
    best = None
    for root, dirs, files in os.walk(repo):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        if "requirements.txt" in files:
            depth = len(Path(root).relative_to(repo).parts)
            if best is None or depth < best[0]:
                best = (depth, Path(root))
    return best[1] if best else None


# ───────────────────────────── scanning (OBSERVED) ─────────────────────────────
REQ_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9_.\-]*)(\[[^\]]*\])?\s*((?:[<>=!~]=?|===)[^;#]*)?")


def parse_requirements(path):
    """Return (active dependencies, commented-out requirement lines)."""
    deps, commented = [], []
    path = Path(path)
    for n, raw in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        line = raw.strip()
        if not line:
            continue
        if line.startswith("#"):
            body = line.lstrip("# ").strip()
            m = REQ_RE.match(body)
            if m and re.search(r"[=<>~!]", body):
                commented.append({"name": m.group(1), "spec": (m.group(3) or "").strip(),
                                  "file": path.name, "line": n})
            continue
        if line.startswith("-"):
            continue
        line = line.split(" #")[0].strip()
        m = REQ_RE.match(line)
        if m:
            deps.append({"name": m.group(1), "spec": (m.group(3) or "").strip() or "(unpinned)",
                         "file": path.name, "line": n})
    return deps, commented


def import_targets(pkg):
    return IMPORT_NAMES.get(pkg.lower(), [pkg.lower().replace("-", "_")])


def load_python_files(repo):
    parsed, failed = [], 0
    for root, dirs, files in os.walk(repo):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in files:
            if not fname.endswith(".py"):
                continue
            full = Path(root) / fname
            try:
                text = full.read_text(encoding="utf-8")
                tree = ast.parse(text)
            except (SyntaxError, UnicodeDecodeError, ValueError):
                failed += 1
                continue
            parsed.append((str(full.relative_to(repo)).replace("\\", "/"), text.splitlines(), tree))
    return parsed, failed


def find_usages(dep_name, parsed):
    """Where is the package imported, and which of its functions/classes are used?"""
    targets = {t.lower() for t in import_targets(dep_name)}
    hits, symbols, seen = [], set(), set()
    for rel, lines, tree in parsed:
        aliases = set()
        for node in ast.walk(tree):
            matched = False
            if isinstance(node, ast.Import):
                for a in node.names:
                    if a.name.split(".")[0].lower() in targets:
                        aliases.add(a.asname or a.name.split(".")[0])
                        matched = True
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                if node.module.split(".")[0].lower() in targets:
                    matched = True
                    for a in node.names:
                        symbols.add(f"{node.module}.{a.name}")
            if matched and (rel, node.lineno) not in seen:
                seen.add((rel, node.lineno))
                hits.append({"file": rel, "line": node.lineno, "code": lines[node.lineno - 1].strip()})
        if aliases:
            for node in ast.walk(tree):
                if (isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name)
                        and node.value.id in aliases):
                    symbols.add(f"{node.value.id}.{node.attr}")
    hits.sort(key=lambda h: (h["file"], h["line"]))
    return hits, sorted(symbols)


def pypi_info(name, pinned):
    """Optional: public package metadata from PyPI (needs internet; off by default)."""
    try:
        req = urllib.request.Request(f"https://pypi.org/pypi/{name}/json",
                                     headers={"User-Agent": "dependency-exit-capsule"})
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.load(r)
    except Exception as e:
        return {"error": str(e)[:120]}

    def first_upload(version):
        files = (data.get("releases") or {}).get(version) or []
        times = [(f.get("upload_time_iso_8601") or f.get("upload_time") or "")[:10] for f in files]
        times = sorted(t for t in times if t)
        return times[0] if times else None

    info = data.get("info", {})
    latest = info.get("version")
    classifiers = info.get("classifiers") or []
    return {"latest": latest, "latest_released": first_upload(latest) if latest else None,
            "pinned": pinned, "pinned_released": first_upload(pinned) if pinned else None,
            "requires_python": info.get("requires_python"),
            "inactive": any("Inactive" in c for c in classifiers)}


def risk_signals(dep, hits, py):
    """Risk indicators computed by code. Returns (signals, level)."""
    s, score = [], 0
    spec = dep["spec"]
    pinned = spec[2:].strip() if spec.startswith("==") else None
    if spec == "(unpinned)":
        s.append("Unpinned: any version can be installed, so builds may change over time")
    elif pinned:
        s.append(f"Exact pin to version {pinned}")
    else:
        s.append(f"Version range {spec}")
    if not hits:
        s.append("No direct import found (transitive dependency, unused, or used outside Python)")
    else:
        s.append(f"Imported in {len({h['file'] for h in hits})} file(s)")
    if py and "error" not in py:
        if py.get("pinned_released"):
            years = (datetime.now() - datetime.strptime(py["pinned_released"], "%Y-%m-%d")).days / 365
            s.append(f"Pinned version released {py['pinned_released']} ({years:.1f} years ago)")
            score += 3 if years >= 5 else 2 if years >= 3 else 1 if years >= 1 else 0
        if py.get("latest_released"):
            late = (datetime.now() - datetime.strptime(py["latest_released"], "%Y-%m-%d")).days / 365
            if late >= 2:
                s.append(f"Newest release on PyPI is {late:.1f} years old: the project may be unmaintained")
                score += 3
        if py.get("latest") and pinned:
            s.append(f"Latest on PyPI: {py['latest']} (released {py.get('latest_released')})")
            try:
                from packaging.version import Version
                if Version(pinned).major < Version(py["latest"]).major:
                    s.append("A newer MAJOR version exists (may contain breaking changes)")
                    score += 2
            except Exception:
                pass
        if py.get("inactive"):
            s.append("PyPI classifier marks the project as Inactive")
            score += 3
        level = "High" if score >= 4 else "Medium" if score >= 2 else "Low"
    else:
        level = "n/a"
        if py and "error" in py:
            s.append(f"PyPI lookup failed: {py['error']}")
    return s, level


def scan_repo(target, use_pypi):
    repo = resolve_target(target)
    req_dir = locate_requirements(repo)
    if req_dir is None:
        raise FileNotFoundError("No requirements.txt found inside that folder.")
    parsed, failed = load_python_files(req_dir)
    deps, commented, req_files = [], [], []
    for fname in ("requirements.txt", "requirements-dev.txt"):
        f = req_dir / fname
        if f.exists():
            req_files.append(fname)
            d, c = parse_requirements(f)
            deps += d
            commented += c
    for d in deps:
        hits, symbols = find_usages(d["name"], parsed)
        pinned = d["spec"][2:].strip() if d["spec"].startswith("==") else None
        py = pypi_info(d["name"], pinned) if use_pypi else None
        signals, level = risk_signals(d, hits, py)
        d.update({"usages": hits, "symbols": symbols, "pypi": py, "signals": signals, "heuristic_risk": level})
    return {"repo_root": str(req_dir), "requirements_files": req_files, "deps": deps,
            "commented": commented, "python_files": len(parsed), "unparsable_files": failed,
            "has_tests": (req_dir / "tests").exists(), "scanned_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "pypi_used": use_pypi}


# ───────────────────────────── Gemma (AI-GENERATED) ─────────────────────────────
def installed_models():
    try:
        res = ollama.list()
        items = res["models"] if isinstance(res, dict) else res.models
        names = []
        for m in items:
            n = m.get("model") if isinstance(m, dict) else getattr(m, "model", None)
            if n and "gemma" in n.lower():
                names.append(n)
        return names, None
    except Exception as e:
        return [], str(e)[:160]


def _text(v, n=500):
    if v is None:
        return ""
    return (v if isinstance(v, str) else json.dumps(v))[:n].strip()


def _parse_json(raw):
    """Parse JSON from a model reply, tolerating fences, chatter and truncation."""
    raw = (raw or "").strip()
    if not raw:
        return None
    candidates = [raw]
    m = re.search(r"\{.*\}", raw, re.DOTALL)
    if m:
        candidates.append(m.group(0))
    start = raw.find("{")
    if start != -1:                      # truncated reply: try to close it
        body = raw[start:]
        candidates += [body + suf for suf in ('"}', '"]}', "}", '"]}', ']}')]
    for c in candidates:
        try:
            data = json.loads(c)
            if isinstance(data, dict):
                return data
        except Exception:
            continue
    return None


def _field(obj, key):
    try:
        return obj[key]
    except Exception:
        return getattr(obj, key, None)


def _chat(model, prompt, use_json, budget):
    kw = dict(model=model, messages=[{"role": "user", "content": prompt}], keep_alive="30m",
              options={"num_ctx": 4096, "num_predict": budget, "temperature": 0})
    if use_json:
        kw["format"] = "json"
    try:                                  # switch off "thinking" so it cannot eat the answer budget
        return ollama.chat(think=False, **kw)
    except TypeError:
        return ollama.chat(**kw)
    except Exception as e:
        if "think" in str(e).lower():
            return ollama.chat(**kw)
        raise


def required_by_of(baseline, name):
    """Packages that need this one (observed with pip show), or None if not checked yet."""
    pk = (baseline or {}).get("packages")
    if not pk:
        return None
    return pk.get(name.lower().replace("_", "-"), {}).get("required_by", [])


def conflict_note(g, req_by):
    """Catch AI advice that contradicts observed evidence."""
    if req_by and g and "error" not in g:
        text = " ".join([g.get("replacement", ""), *g.get("migration_steps", [])]).lower()
        if re.search(r"\b(remove|delete|uninstall|drop)\b", text):
            return ("Gemma suggests removing this package, but the test environment shows it is required by: "
                    + ", ".join(req_by) + ". Removing it could break those packages.")
    return None


def ask_gemma(model, dep, py_version, required_by=None):
    locs = "; ".join(f"{h['file']}:{h['line']}" for h in dep["usages"][:8]) or "none found"
    if required_by is None:
        rb = "NOT CHECKED (so never recommend removing the package)"
    else:
        rb = ", ".join(required_by) or "no other installed package"
    facts = [f"Package: {dep['name']}", f"Declared as: {dep['spec']} (in {dep['file']})",
             f"Python version used by the project: {py_version}",
             f"Imported at: {locs}",
             f"Functions/classes used: {', '.join(dep['symbols'][:10]) or 'none detected'}",
             f"Required by other installed packages: {rb}"]
    py = dep.get("pypi")
    if py and "error" not in py:
        facts.append(f"PyPI: pinned release date {py.get('pinned_released')}, latest {py.get('latest')} "
                     f"released {py.get('latest_released')}")
    prompt = (
        "You are helping an open-source maintainer plan a safe dependency replacement.\n"
        "FACTS (observed by a scanner, trust these):\n- " + "\n- ".join(facts) + "\n\n"
        "A package with no direct import can still be needed by another package. "
        "Never recommend removing a package that is required by another package or whose status is NOT CHECKED.\n"
        "Reply with ONLY a JSON object with these keys, and keep every value under 25 words:\n"
        '"risk": one of "low","medium","high","unsure"\n'
        '"reason": maintenance or compatibility risk (do not discuss security CVEs)\n'
        '"replacement": best replacement package or approach, or "none needed"\n'
        '"migration_steps": a list of at most 4 short steps specific to the facts above\n'
        '"suggested_test": one test that would prove the migration is safe\n'
        'If you are not sure about something, write "unsure" instead of guessing.'
    )
    t0 = time.time()
    data, raw, reason = None, "", None
    try:
        for use_json, budget, extra in ((True, 1200, ""), (False, 1500, "\nReturn the JSON object only. No markdown, no commentary.")):
            r = _chat(model, prompt + extra, use_json, budget)
            raw = (_field(_field(r, "message"), "content") or "")
            reason = _field(r, "done_reason")
            data = _parse_json(raw)
            if data:
                break
    except Exception as e:
        return {"error": f"Could not reach Ollama/model: {str(e)[:200]}", "model": model}
    if not data:
        return {"error": "Gemma did not return usable JSON", "raw": raw[:600] or "(empty reply)",
                "done_reason": str(reason), "model": model}
    steps = data.get("migration_steps")
    steps = [steps] if isinstance(steps, str) else (steps if isinstance(steps, list) else [])
    risk = _text(data.get("risk"), 12).lower()
    return {"risk": risk if risk in ("low", "medium", "high") else "unsure",
            "reason": _text(data.get("reason")), "replacement": _text(data.get("replacement"), 200),
            "migration_steps": [_text(x, 300) for x in steps][:4],
            "suggested_test": _text(data.get("suggested_test")),
            "model": model, "seconds": round(time.time() - t0, 1)}


# ───────────────────────────── verification (OBSERVED) ─────────────────────────────
def parse_pytest(output, rc):
    tail_lines = [l for l in output.strip().splitlines() if l.strip()][-6:]
    summary = " ".join(tail_lines)
    counts = {k: 0 for k in ("passed", "failed", "error", "skipped")}
    for num, word in re.findall(r"(\d+) (passed|failed|errors?|skipped)", summary):
        counts["error" if word.startswith("error") else word] += int(num)
    failed = sorted({re.split(r"\s+-\s+", l.split(" ", 1)[1].strip(), maxsplit=1)[0] for l in output.splitlines()
                     if l.startswith(("FAILED ", "ERROR "))})
    warns = []
    for l in output.splitlines():
        if re.search(r"(Pending)?DeprecationWarning|FutureWarning", l) and l.strip() not in warns:
            warns.append(l.strip()[:220])
    return {"return_code": rc, **counts, "failed_tests": failed, "deprecation_warnings": warns[:12],
            "summary_line": tail_lines[-1] if tail_lines else ""}


def parse_pip_show(out):
    info = {}
    for block in re.split(r"^---\s*$", out, flags=re.M):
        d = {}
        for line in block.strip().splitlines():
            if ": " in line:
                k, v = line.split(": ", 1)
                d[k.strip()] = v.strip()
        if d.get("Name"):
            info[d["Name"].lower().replace("_", "-")] = {
                "version": d.get("Version", ""),
                "required_by": [x.strip() for x in d.get("Required-by", "").split(",") if x.strip()]}
    return info


def build_and_test(repo_dir, label, base_python, step=lambda m: None):
    """Create a clean venv, install the requirements, run pytest. Everything here is evidence."""
    repo_dir = Path(repo_dir)
    res = {"label": label, "commands": [], "install_ok": False, "tests": None, "logs": {}}
    venv_dir = WORK_DIR / f"venv_{label}"
    _rm(venv_dir)
    WORK_DIR.mkdir(parents=True, exist_ok=True)
    step("Creating a clean virtual environment...")
    rc, out, _ = run([base_python, "-m", "venv", str(venv_dir)])
    res["commands"].append(f"{base_python} -m venv {venv_dir.name}")
    if rc != 0:
        res["logs"]["venv"] = tail(out)
        return res
    py = venv_python(venv_dir)
    _, ver, _ = run([py, "--version"])
    res["python_version"] = ver.strip()
    reqs = [f for f in ("requirements.txt", "requirements-dev.txt") if (repo_dir / f).exists()]
    step(f"Installing {', '.join(reqs)} (this can take a minute)...")
    cmd = [py, "-m", "pip", "install", "-q"] + [x for r in reqs for x in ("-r", r)]
    res["commands"].append("pip install " + " ".join(f"-r {r}" for r in reqs))
    rc, out, dt = run(cmd, cwd=repo_dir)
    res["logs"]["install"] = tail(out)
    if rc != 0:
        res["install_error"] = tail(out, 700)
        return res
    res["install_ok"] = True
    names = []
    for r in reqs:
        names += [d["name"] for d in parse_requirements(repo_dir / r)[0]]
    _, show_out, _ = run([py, "-m", "pip", "show"] + names, cwd=repo_dir)
    res["packages"] = parse_pip_show(show_out)
    if run([py, "-m", "pytest", "--version"], cwd=repo_dir)[0] != 0:
        run([py, "-m", "pip", "install", "-q", "pytest"], cwd=repo_dir)
    step("Running the test suite...")
    res["commands"].append("python -m pytest -q -rfE -p no:cacheprovider")
    rc, out, dt = run([py, "-m", "pytest", "-q", "-rfE", "-p", "no:cacheprovider"], cwd=repo_dir, timeout=600)
    res["tests"] = parse_pytest(out, rc)
    res["tests"]["seconds"] = round(dt, 1)
    res["logs"]["tests"] = tail(out)
    return res


def patch_imports(dest, dep, hits, new_import):
    """Mechanically rewrite import lines to use the replacement. Unsupported lines are listed."""
    changed, manual, files = 0, [], set()
    by_file = {}
    for h in hits:
        by_file.setdefault(h["file"], []).append(h)
    olds = import_targets(dep["name"])
    for rel, hs in by_file.items():
        p = Path(dest) / rel
        lines = p.read_text(encoding="utf-8").splitlines(keepends=True)
        for h in hs:
            raw = lines[h["line"] - 1]
            body, end = raw.rstrip("\r\n"), raw[len(raw.rstrip("\r\n")):]
            new_line = None
            for old in olds:
                o = re.escape(old)
                m = re.match(rf"^(\s*)from\s+{o}\s+import\b(.*)$", body)
                if m:
                    new_line = f"{m.group(1)}from {new_import} import{m.group(2)}"
                    break
                m = re.match(rf"^(\s*)import\s+{o}\s*(#.*)?$", body)
                if m:
                    new_line = f"{m.group(1)}import {new_import} as {old}" + (f"  {m.group(2)}" if m.group(2) else "")
                    break
                m = re.match(rf"^(\s*)import\s+{o}\s+as\s+(\w+)\s*(#.*)?$", body)
                if m:
                    new_line = f"{m.group(1)}import {new_import} as {m.group(2)}" + (f"  {m.group(3)}" if m.group(3) else "")
                    break
            if new_line is None:
                manual.append(h)
            else:
                lines[h["line"] - 1] = new_line + end
                changed += 1
                files.add(rel)
        p.write_text("".join(lines), encoding="utf-8")
    return {"lines_changed": changed, "files_changed": sorted(files), "manual_needed": manual}


def patch_requirements(dest, dep_name, new_pip):
    changed = []
    norm = lambda s: s.lower().replace("_", "-")
    for fname in ("requirements.txt", "requirements-dev.txt"):
        f = Path(dest) / fname
        if not f.exists():
            continue
        out, touched = [], False
        for line in f.read_text(encoding="utf-8").splitlines():
            m = REQ_RE.match(line.strip()) if not line.strip().startswith("#") else None
            if m and norm(m.group(1)) == norm(dep_name):
                touched = True
                if new_pip:
                    out.append(new_pip)
                continue
            out.append(line)
        if touched:
            f.write_text("\n".join(out) + "\n", encoding="utf-8")
            changed.append(fname)
    return changed


def run_experiment(scan, dep, new_pip, new_import, base_python, baseline, step=lambda m: None):
    repo_root = Path(scan["repo_root"])
    dest = WORK_DIR / "experiment_repo"
    _rm(dest)
    step("Copying the repository into a scratch folder (your original is never modified)...")
    shutil.copytree(repo_root, dest, ignore=shutil.ignore_patterns(*SKIP_DIRS, "*.pyc"))
    step("Applying the migration (requirements + imports)...")
    req_changed = patch_requirements(dest, dep["name"], new_pip)
    if new_import.lower() in [o.lower() for o in import_targets(dep["name"])]:
        patch = {"lines_changed": 0, "files_changed": [], "manual_needed": []}   # same import name: version change only
    else:
        patch = patch_imports(dest, dep, dep["usages"], new_import)
    res = build_and_test(dest, "experiment", base_python, step)
    res.update({"dependency": dep["name"], "replacement_pip": new_pip or "(none, standard library)",
                "replacement_import": new_import, "requirements_changed": req_changed, "patch": patch})
    gaps = []
    if patch["manual_needed"]:
        gaps.append(f"{len(patch['manual_needed'])} import line(s) could not be rewritten automatically and "
                    "need manual migration: " + ", ".join(f"{h['file']}:{h['line']}" for h in patch["manual_needed"]))
    if not res["install_ok"]:
        gaps.append("Installing the dependencies failed after the replacement. See the install log.")
    elif res["tests"]:
        t = res["tests"]
        b = baseline["tests"] if baseline and baseline.get("tests") else None
        if b:
            new_fail = sorted(set(t["failed_tests"]) - set(b["failed_tests"]))
            fixed = sorted(set(b["failed_tests"]) - set(t["failed_tests"]))
            if new_fail:
                gaps.append(f"{len(new_fail)} test(s) pass with the original dependency but FAIL with the replacement: "
                            + "; ".join(new_fail[:8]))
            if fixed:
                gaps.append(f"{len(fixed)} test(s) that failed before now pass: " + "; ".join(fixed[:8]))
            if not new_fail and not patch["manual_needed"]:
                gaps.append("No new test failures observed. This is limited to what the existing tests cover.")
            if len(t["deprecation_warnings"]) != len(b["deprecation_warnings"]):
                gaps.append(f"Deprecation warnings changed: {len(b['deprecation_warnings'])} -> {len(t['deprecation_warnings'])}")
        else:
            gaps.append("No baseline run to compare against. Run the baseline tests first.")
    res["gaps"] = gaps
    return res


# ───────────────────────────── capsule ─────────────────────────────
def build_capsule(state, model):
    scan = state["scan"]
    ai = state.get("ai", {})
    exps = state.get("experiments", {})
    deps = []
    for d in scan["deps"]:
        deps.append({"name": d["name"], "declared": d["spec"], "source": f"{d['file']}:{d['line']}",
                     "observed": {"usage_locations": d["usages"], "api_used": d["symbols"],
                                  "installed_version": ((state.get("baseline") or {}).get("packages") or {}).get(d["name"].lower().replace("_", "-"), {}).get("version"),
                                  "required_by": required_by_of(state.get("baseline"), d["name"]),
                                  "risk_indicators": d["signals"], "heuristic_risk": d["heuristic_risk"],
                                  "pypi": d["pypi"]},
                     "ai_generated": ai.get(d["name"]),
                     "conflict_with_evidence": conflict_note(ai.get(d["name"]), required_by_of(state.get("baseline"), d["name"])),
                     "executed_experiment": d["name"] in exps})
    gaps = [{"dependency": n, "gaps": e.get("gaps", [])} for n, e in exps.items()]
    concerns = list(LIMITATIONS)
    verified = set(exps)
    unverified = [d["name"] for d in scan["deps"] if d["name"] not in verified]
    concerns.insert(0, f"{len(unverified)} of {len(scan['deps'])} dependencies have NOT been verified by an executed experiment.")
    return {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "target_repository": {"path": scan["repo_root"], "requirements_files": scan["requirements_files"],
                              "python_files_scanned": scan["python_files"], "scanned_at": scan["scanned_at"]},
        "ai_model": {"name": "Gemma 4", "ollama_tag": model, "source": "Ollama library (weights by Google DeepMind)",
                     "access_method": "Local, via the Ollama runtime. No cloud or paid API.",
                     "license": "Apache 2.0 (confirm on the model page)",
                     "role": "Writes risk opinions, replacement proposals, migration steps and suggested tests "
                             "from facts the scanner observed. Its output is never treated as verified."},
        "dependencies": deps,
        "commented_out_requirements": scan["commented"],
        "verification": {"baseline": state.get("baseline"), "experiments": list(exps.values())},
        "compatibility_gaps": gaps,
        "open_concerns_and_limitations": concerns,
    }


def _tests_line(t):
    if not t:
        return "tests did not run"
    return f"{t['passed']} passed, {t['failed']} failed, {t['error']} errors, {t['skipped']} skipped"


def capsule_markdown(c):
    L = []
    a = L.append
    a("# Dependency Exit Capsule\n")
    a(f"Generated {c['generated_at']}. Target: `{c['target_repository']['path']}` "
      f"({c['target_repository']['python_files_scanned']} Python files scanned).\n")
    a("> **How to read this document.** Sections marked **OBSERVED** were produced by code that inspected the "
      "repository or ran commands. Sections marked **AI-GENERATED** are Gemma's suggestions and were not verified "
      "unless an executed experiment says so.\n")
    m = c["ai_model"]
    a("## AI model details\n")
    a(f"- Model: {m['name']} (`{m['ollama_tag']}`)\n- Source: {m['source']}\n- Access: {m['access_method']}\n"
      f"- License: {m['license']}\n- Role: {m['role']}\n")
    a("## Summary (OBSERVED)\n")
    a("| Dependency | Declared | Direct imports | Heuristic risk | Experiment run |")
    a("|---|---|---|---|---|")
    for d in c["dependencies"]:
        a(f"| {d['name']} | `{d['declared']}` | {len(d['observed']['usage_locations'])} | "
          f"{d['observed']['heuristic_risk']} | {'yes' if d['executed_experiment'] else 'no'} |")
    a("")
    if c["commented_out_requirements"]:
        a("Commented-out requirement lines (ignored): " +
          ", ".join(f"`{x['name']}{x['spec']}` ({x['file']}:{x['line']})" for x in c["commented_out_requirements"]) + "\n")
    a("## Dependencies\n")
    for d in c["dependencies"]:
        o, g = d["observed"], d["ai_generated"]
        a(f"### {d['name']}\n")
        a(f"**OBSERVED**\n\n- Declared: `{d['declared']}` at {d['source']}")
        for s in o["risk_indicators"]:
            a(f"- Risk indicator: {s}")
        a(f"- Usage locations: " + ("; ".join(f"`{h['file']}:{h['line']}`" for h in o["usage_locations"]) or "none found"))
        if o["api_used"]:
            a("- Functions/classes used: " + ", ".join(f"`{x}`" for x in o["api_used"][:12]))
        if o["required_by"] is None:
            a("- Required by other packages: not checked (run the baseline tests to find out)")
        else:
            a("- Required by other packages (pip show): " + (", ".join(o["required_by"]) or "none"))
        if o.get("installed_version"):
            a(f"- Installed version in the test environment: {o['installed_version']}")
        a("")
        if g and "error" not in g:
            a(f"**AI-GENERATED** (Gemma `{g['model']}`, unverified)\n")
            a(f"- Risk opinion: {g['risk']}\n- Reason: {g['reason']}\n- Proposed replacement: {g['replacement']}")
            for i, s in enumerate(g["migration_steps"], 1):
                a(f"- Migration step {i}: {s}")
            a(f"- Suggested test: {g['suggested_test']}")
            if d.get("conflict_with_evidence"):
                a(f"- **Conflict with observed evidence:** {d['conflict_with_evidence']}")
            a("")
        elif g:
            a(f"**AI-GENERATED**: analysis failed ({g['error']})\n")
        else:
            a("**AI-GENERATED**: not analysed yet.\n")
    a("## Executed test results (OBSERVED)\n")
    b = c["verification"]["baseline"]
    if b:
        a(f"**Baseline, original dependencies** ({b.get('python_version', '?')}): "
          + (_tests_line(b["tests"]) if b["install_ok"] else "dependency installation FAILED"))
        if b.get("install_error"):
            a("```\n" + b["install_error"] + "\n```")
        if b["tests"] and b["tests"]["deprecation_warnings"]:
            a("\nDeprecation warnings seen while testing:")
            for w in b["tests"]["deprecation_warnings"][:6]:
                a(f"- `{w}`")
        a("")
    else:
        a("Baseline tests were not run.\n")
    for e in c["verification"]["experiments"]:
        a(f"**Replacement experiment: {e['dependency']} -> {e['replacement_pip']}** (import `{e['replacement_import']}`): "
          + (_tests_line(e["tests"]) if e["install_ok"] else "dependency installation FAILED"))
        a(f"- Import lines rewritten: {e['patch']['lines_changed']} in {', '.join(e['patch']['files_changed']) or 'no files'}")
        a("- Commands: " + "; ".join(f"`{x}`" for x in e["commands"]) + "\n")
    a("## Compatibility gaps (OBSERVED)\n")
    if any(x["gaps"] for x in c["compatibility_gaps"]):
        for x in c["compatibility_gaps"]:
            for gp in x["gaps"]:
                a(f"- **{x['dependency']}**: {gp}")
    else:
        a("No experiments were executed, so no compatibility gaps could be observed.")
    a("\n## Open concerns and limitations\n")
    for x in c["open_concerns_and_limitations"]:
        a(f"- {x}")
    return "\n".join(L) + "\n"


# ───────────────────────────── UI ─────────────────────────────
CSS = """
<style>
.block-container {padding-top: 1.6rem; max-width: 1180px;}
.banner {background: linear-gradient(120deg,#0f172a 0%,#1e3a5f 60%,#0f766e 100%); color:#f8fafc;
  padding: 1.5rem 1.8rem; border-radius: 14px; margin-bottom: 1rem;}
.banner h1 {color:#f8fafc; font-size: 1.9rem; margin:0 0 .25rem 0; padding:0;}
.banner p {color:#cbd5e1; margin:0; font-size: .98rem;}
.tag {display:inline-block; padding: .12rem .6rem; border-radius: 999px; font-size:.78rem; font-weight:600; margin-right:.4rem;}
.tag-obs {background: rgba(22,163,74,.16); color:#16a34a; border:1px solid rgba(22,163,74,.4);}
.tag-ai {background: rgba(124,58,237,.14); color:#8b5cf6; border:1px solid rgba(124,58,237,.4);}
.tag-warn {background: rgba(217,119,6,.14); color:#d97706; border:1px solid rgba(217,119,6,.4);}
.note {border-left: 4px solid #8b5cf6; padding: .4rem .9rem; margin: .4rem 0 .8rem 0; background: rgba(139,92,246,.07); border-radius: 0 8px 8px 0;}
.note-obs {border-left-color:#16a34a; background: rgba(22,163,74,.07);}
</style>
"""
RISK_ICON = {"High": "🔴 High", "Medium": "🟠 Medium", "Low": "🟢 Low", "n/a": "⚪ n/a",
             "high": "🔴 high", "medium": "🟠 medium", "low": "🟢 low", "unsure": "⚪ unsure"}


def tag(kind, text):
    return f'<span class="tag tag-{kind}">{text}</span>'


def init_state():
    for k, v in {"scan": None, "ai": {}, "baseline": None, "experiments": {}}.items():
        st.session_state.setdefault(k, v)


def main():
    st.set_page_config(page_title="Verifi", page_icon="📦", layout="wide")
    st.markdown(CSS, unsafe_allow_html=True)
    init_state()
    S = st.session_state

    st.markdown('<div class="banner"><h1>Verifi</h1>'
                '<p>Find risky dependencies in a real repository, ask a local Gemma 4 model how to replace them, '
                'then prove it by running the tests. Everything runs on this laptop.</p></div>',
                unsafe_allow_html=True)

    # ── sidebar
    with st.sidebar:
        st.header("Setup")
        target = st.text_input("Target repository", placeholder=r"C:\path\to\LinkWatch  or  https://github.com/rishrek/LinkWatch",
                               help="A local folder, or a GitHub URL that will be cloned.")
        names, err = installed_models()
        options = names or DEFAULT_MODELS
        model = st.selectbox("Gemma 4 model (local)", options,
                             help="Smaller is faster. Only models installed in Ollama appear here.")
        if err:
            st.warning("Ollama is not reachable. Start the Ollama app, then reload this page.")
        elif not names:
            st.warning("No Gemma model is installed yet. Run: ollama pull gemma4:e2b")
        use_pypi = st.checkbox("Look up release dates on PyPI (internet)", value=False,
                               help="Adds evidence like how old a pinned version is. Only enable if the organizers "
                                    "confirm internet lookups are allowed. Gemma itself never uses the internet.")
        base_python = st.text_input("Python for test environments", value=sys.executable,
                                    help="Must be Python 3.12 or 3.13 for LinkWatch.")
        v = sys.version_info
        if (v.major, v.minor) not in ((3, 12), (3, 13)):
            st.warning(f"This app runs on Python {v.major}.{v.minor}. LinkWatch needs 3.12 or 3.13. "
                       "Point the box above at a 3.12/3.13 python.exe.")
        st.caption("Tip: add `.capsule_work/` and `capsule_output/` to .gitignore if you do not want them in your repo.")

    t1, t2, t3, t4 = st.tabs(["1 · Scan", "2 · Gemma analysis", "3 · Verify with tests", "4 · Exit Capsule"])

    # ── tab 1
    with t1:
        st.markdown(tag("obs", "OBSERVED") + "Found by code reading the repository. No AI involved.", unsafe_allow_html=True)
        if st.button("Scan repository", type="primary"):
            if not target.strip():
                st.error("Enter a repository folder or GitHub URL in the sidebar first.")
            else:
                try:
                    with st.spinner("Scanning requirements and Python files..."):
                        S.scan = scan_repo(target, use_pypi)
                    S.ai, S.baseline, S.experiments = {}, None, {}
                except Exception as e:
                    st.error(str(e))
        scan = S.scan
        if scan:
            c = st.columns(4)
            c[0].metric("Dependencies", len(scan["deps"]))
            c[1].metric("Imported directly", sum(1 for d in scan["deps"] if d["usages"]))
            c[2].metric("Python files scanned", scan["python_files"])
            c[3].metric("Test suite found", "yes" if scan["has_tests"] else "no")
            st.caption(f"Scanned `{scan['repo_root']}` at {scan['scanned_at']}. Files read: {', '.join(scan['requirements_files'])}")
            rows = []
            for d in scan["deps"]:
                py = d["pypi"] if d["pypi"] and "error" not in d["pypi"] else {}
                where = ", ".join(f"{h['file']}:{h['line']}" for h in d["usages"][:2])
                if len(d["usages"]) > 2:
                    where += f" (+{len(d['usages']) - 2} more)"
                rows.append({"Package": d["name"], "Declared": d["spec"], "Source": d["file"],
                             "Direct imports": len(d["usages"]), "Where it is used": where or "none found",
                             "Pinned release": py.get("pinned_released") or "-",
                             "Latest on PyPI": py.get("latest") or "-",
                             "Heuristic risk": RISK_ICON[d["heuristic_risk"]]})
            st.dataframe(rows, hide_index=True)
            if scan["commented"]:
                st.info("Ignored commented-out lines: " + ", ".join(f"`{x['name']}{x['spec']}` ({x['file']}:{x['line']})" for x in scan["commented"]))
            if not scan["pypi_used"]:
                st.caption("Heuristic risk needs the PyPI lookup (sidebar). Without it, only pin type and import evidence are shown.")
            pick = st.selectbox("Inspect one dependency", [d["name"] for d in scan["deps"]])
            d = next(x for x in scan["deps"] if x["name"] == pick)
            cc = st.columns(2)
            with cc[0]:
                st.markdown("**Risk indicators**")
                for s in d["signals"]:
                    st.markdown(f"- {s}")
            with cc[1]:
                st.markdown("**How it is used**")
                st.code("\n".join(f"{h['file']}:{h['line']}   {h['code']}" for h in d["usages"]) or "No direct import found", language="text")
                if d["symbols"]:
                    st.caption("Functions/classes used: " + ", ".join(d["symbols"][:12]))
        else:
            st.info("Enter the repository in the sidebar, then click **Scan repository**.")

    # ── tab 2
    with t2:
        st.markdown(tag("ai", "AI-GENERATED") + "Gemma's suggestions. Not verified until you run a test in step 3.", unsafe_allow_html=True)
        if not S.scan:
            st.info("Scan a repository first.")
        else:
            deps = S.scan["deps"]
            chosen = st.multiselect("Dependencies to analyze", [d["name"] for d in deps], default=[d["name"] for d in deps])
            st.caption("Each dependency is a separate short question, so answers stay focused. "
                       "On a laptop CPU expect roughly 10 to 40 seconds each with the small model.")
            if not (S.baseline and S.baseline.get("packages")):
                st.warning("Run the baseline tests in step 3 first if you can. They reveal which packages are "
                           "needed by other packages, so Gemma is not guessing about 'unused' dependencies.")
            failed = [n for n, g in S.ai.items() if "error" in g]
            b1, b2 = st.columns([1, 1])
            go_all = b1.button("Analyze with Gemma", type="primary", disabled=not chosen)
            go_retry = b2.button(f"Retry the {len(failed)} that failed", disabled=not failed)
            todo = chosen if go_all else failed if go_retry else []
            if todo:
                bar = st.progress(0.0, text="Starting...")
                pyv = f"{sys.version_info.major}.{sys.version_info.minor}"
                for i, name in enumerate(todo):
                    bar.progress(i / len(todo), text=f"Asking Gemma about {name} ({i + 1} of {len(todo)})")
                    S.ai[name] = ask_gemma(model, next(x for x in deps if x["name"] == name), pyv,
                                           required_by_of(S.baseline, name))
                bar.progress(1.0, text="Done")
            if S.ai:
                rows = []
                for d in deps:
                    g = S.ai.get(d["name"])
                    if g:
                        rows.append({"Package": d["name"], "Observed (heuristic)": RISK_ICON[d["heuristic_risk"]],
                                     "Gemma's opinion": RISK_ICON[g["risk"]] if "risk" in g else "⚠️ failed",
                                     "Proposed replacement": g.get("replacement", g.get("error", ""))})
                st.dataframe(rows, hide_index=True)
                for d in deps:
                    g = S.ai.get(d["name"])
                    if not g:
                        continue
                    with st.expander(f"{d['name']}  {d['spec']}"):
                        if "error" in g:
                            st.error(g["error"])
                            if g.get("raw"):
                                st.caption(f"Stopped because: {g.get('done_reason')}. Raw reply from the model:")
                                st.code(g["raw"], language="text")
                            continue
                        st.markdown(f'<div class="note">{tag("ai", "AI-GENERATED")} answered by {g["model"]} in {g["seconds"]}s</div>', unsafe_allow_html=True)
                        st.markdown(f"**Reason:** {g['reason']}")
                        st.markdown(f"**Proposed replacement:** {g['replacement']}")
                        st.markdown("**Migration steps**")
                        for s in g["migration_steps"]:
                            st.markdown(f"- {s}")
                        st.markdown(f"**Suggested test:** {g['suggested_test']}")
                        note = conflict_note(g, required_by_of(S.baseline, d["name"]))
                        if note:
                            st.warning("Conflict with observed evidence: " + note)

    # ── tab 3
    with t3:
        st.markdown(tag("obs", "OBSERVED") + "Real commands run in clean virtual environments. The output below is evidence.", unsafe_allow_html=True)
        if not S.scan:
            st.info("Scan a repository first.")
        else:
            scan = S.scan
            st.subheader("A. Baseline: original dependencies")
            if st.button("Run baseline tests"):
                with st.status("Running baseline...", expanded=True) as status:
                    S.baseline = build_and_test(scan["repo_root"], "baseline", base_python, lambda m: status.write(m))
                    ok = S.baseline["install_ok"] and S.baseline["tests"]
                    status.update(label="Baseline finished" if ok else "Baseline hit a problem", state="complete" if ok else "error")
            b = S.baseline
            if b:
                if not b["install_ok"]:
                    st.error("Installing the repository's original dependencies failed. That is itself a finding.")
                    st.code(b.get("install_error", b["logs"].get("venv", "")), language="text")
                elif b["tests"]:
                    t = b["tests"]
                    m = st.columns(5)
                    m[0].metric("Passed", t["passed"])
                    m[1].metric("Failed", t["failed"])
                    m[2].metric("Errors", t["error"])
                    m[3].metric("Deprecation warnings", len(t["deprecation_warnings"]))
                    m[4].metric("Python", b.get("python_version", "?").replace("Python ", ""))
                    if t["failed_tests"]:
                        st.code("\n".join(t["failed_tests"]), language="text")
                    if b.get("packages"):
                        with st.expander("Installed versions and which packages need each one (observed)"):
                            st.dataframe([{"Package": d["name"],
                                           "Installed": b["packages"].get(d["name"].lower().replace("_", "-"), {}).get("version", "-"),
                                           "Required by": ", ".join(b["packages"].get(d["name"].lower().replace("_", "-"), {}).get("required_by", [])) or "nothing else"}
                                          for d in scan["deps"]], hide_index=True)
                    with st.expander("Test output"):
                        st.code(b["logs"]["tests"], language="text")

            st.subheader("B. Replacement experiment")
            st.caption("Copies the repo, swaps one dependency, rewrites its imports, builds a fresh environment and runs the tests again. Your original folder is never changed.")
            names = [d["name"] for d in scan["deps"]]
            dep_name = st.selectbox("Dependency to replace", names, key="exp_dep")
            dep = next(x for x in scan["deps"] if x["name"] == dep_name)
            g = S.ai.get(dep_name)
            if g and "replacement" in g:
                st.markdown(f'<div class="note">{tag("ai", "AI-GENERATED")} Gemma suggested: <b>{g["replacement"]}</b></div>', unsafe_allow_html=True)
            preset = PRESETS.get(dep_name, ("", ""))
            c1, c2 = st.columns(2)
            new_pip = c1.text_input("Replacement package or version, as written in requirements (e.g. platformdirs or Jinja2>=3.1; empty = standard library)", value=preset[0], key=f"pip_{dep_name}")
            new_imp = c2.text_input("Replacement import name", value=preset[1], key=f"imp_{dep_name}")
            if dep_name in PRESETS:
                st.caption("Prefilled with a common drop-in suggestion. Edit it freely.")
            if not dep["usages"]:
                st.warning("No direct imports were found for this dependency, so there is nothing to rewrite.")
            if st.button("Run replacement experiment", type="primary", disabled=not (dep["usages"] and new_imp.strip())):
                with st.status(f"Testing {dep_name} -> {new_pip or new_imp}", expanded=True) as status:
                    S.experiments[dep_name] = run_experiment(scan, dep, new_pip.strip(), new_imp.strip(), base_python, S.baseline, lambda m: status.write(m))
                    status.update(label="Experiment finished", state="complete")
            for name, e in S.experiments.items():
                with st.expander(f"Result: {name} -> {e['replacement_pip']}", expanded=(name == dep_name)):
                    if not e["install_ok"]:
                        st.error("Installing dependencies failed after the swap.")
                        st.code(e.get("install_error", ""), language="text")
                    elif e["tests"]:
                        t = e["tests"]
                        m = st.columns(3)
                        m[0].metric("Passed", t["passed"])
                        m[1].metric("Failed", t["failed"])
                        m[2].metric("Errors", t["error"])
                        if t["failed_tests"]:
                            st.code("\n".join(t["failed_tests"]), language="text")
                    st.markdown("**Compatibility gaps**")
                    for gp in e["gaps"] or ["None recorded."]:
                        st.markdown(f"- {gp}")
                    st.caption(f"Import lines rewritten: {e['patch']['lines_changed']} in {', '.join(e['patch']['files_changed']) or 'no files'}")
                    if e["logs"].get("tests"):
                        with st.expander("Test output"):
                            st.code(e["logs"]["tests"], language="text")

    # ── tab 4
    with t4:
        if not S.scan:
            st.info("Scan a repository first.")
        else:
            capsule = build_capsule(S, model)
            md = capsule_markdown(capsule)
            st.markdown(tag("obs", "OBSERVED") + tag("ai", "AI-GENERATED") + "Kept in separate sections inside the capsule.", unsafe_allow_html=True)
            c = st.columns(4)
            c[0].metric("Dependencies", len(capsule["dependencies"]))
            c[1].metric("Analysed by Gemma", len([x for x in S.ai.values() if "error" not in x]))
            c[2].metric("Baseline run", "yes" if S.baseline else "no")
            c[3].metric("Experiments run", len(S.experiments))
            d1, d2 = st.columns(2)
            d1.download_button("Download capsule (Markdown)", md, file_name="dependency_exit_capsule.md", mime="text/markdown")
            d2.download_button("Download capsule (JSON)", json.dumps(capsule, indent=2), file_name="dependency_exit_capsule.json", mime="application/json")
            if st.button("Save a copy in capsule_output/"):
                OUT_DIR.mkdir(exist_ok=True)
                (OUT_DIR / "dependency_exit_capsule.md").write_text(md, encoding="utf-8")
                (OUT_DIR / "dependency_exit_capsule.json").write_text(json.dumps(capsule, indent=2), encoding="utf-8")
                st.success(f"Saved to {OUT_DIR}")
            st.markdown("---")
            st.markdown(md)


if __name__ == "__main__":
    main()
