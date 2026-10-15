# [ProjectName] - Dependency Exit Capsule Builder

**Team:** [TeamName] | **Members:** [Name 1, Name 2, Name 3]
**Event:** Hacktoberfest Hack Day Mumbai x ISTE KJSSE (Abhyantriki 2026), 15 October 2026
**Track:** Track 1 - Gemma 4: Dependency Resilience

## 1. Problem and solution overview

Open-source projects depend on third-party packages that can become outdated, unmaintained or
incompatible. Maintainers often find out only after something breaks, and AI suggestions alone are
not reliable enough to act on.

This tool takes a real Python repository (the organizer-provided **LinkWatch**), and:

1. **Scans** its requirements and finds exactly where each dependency is imported (observed by code).
2. **Asks a local Gemma 4 model** for a risk opinion, a replacement, migration steps and a suggested test (AI-generated).
3. **Verifies by running the repository's real tests** in clean virtual environments, first with the original
   dependencies and then with a proposed replacement, and compares the results (observed by execution).
4. **Exports a Dependency Exit Capsule** (Markdown and JSON) in which AI suggestions and observed evidence
   are kept in clearly separate sections.

It also checks Gemma's advice against evidence. For example, if Gemma suggests removing a package that
`pip show` reports is required by another package, the tool flags the conflict.

## 2. Setup instructions

Requirements: Windows/macOS/Linux, **Python 3.12 or 3.13** (LinkWatch does not support 3.14), Git, and [Ollama](https://ollama.com).

```
git clone https://github.com/[YOUR-USERNAME]/[REPO-NAME].git
cd [REPO-NAME]
py -3.12 -m venv .venv            # Windows (use python3.12 on macOS/Linux)
.venv\Scripts\activate.bat        # Windows (source .venv/bin/activate on macOS/Linux)
python -m pip install -r requirements.txt
ollama pull gemma4:e2b
python -m streamlit run app.py
```

The app opens at http://localhost:8501. Ollama must be running (its tray icon is visible, or open the Ollama app).

## 3. Usage instructions

1. In the sidebar, enter the **target repository**: a local folder path or a GitHub URL (it will be cloned).
   Check that "Python for test environments" points to a Python 3.12/3.13 executable.
2. **1 - Scan:** click *Scan repository* to list every dependency with its usage locations.
3. **3 - Verify:** click *Run baseline tests* to build a clean environment and run the repo's tests.
   (Do this before step 2 for best results: it reveals which packages are needed by other packages.)
4. **2 - Gemma analysis:** choose dependencies and click *Analyze with Gemma*.
5. **3 - Verify (experiment):** pick a dependency, enter a replacement (for example `platformdirs`, or
   `Jinja2>=3.1`), and click *Run replacement experiment*. The tool copies the repo, swaps the dependency,
   rewrites imports, rebuilds a fresh environment and reruns the tests.
6. **4 - Exit Capsule:** download the capsule as Markdown or JSON.

An example capsule from a real run is in [`examples/`](examples/).

## 4. Architecture

```
 target repo (folder or GitHub URL)
        |
        v
 [Scanner: ast + requirements parser] -----> OBSERVED: dependencies, usage locations, risk indicators
        |
        v
 [Baseline: clean venv -> pip install -> pytest] -> OBSERVED: test results, installed versions, "required by"
        |
        v
 [Gemma 4 via local Ollama] --facts as input--> AI-GENERATED: risk opinion, replacement, steps, test idea
        |
        v
 [Experiment: copy repo -> swap dependency -> rewrite imports -> new venv -> pytest] -> OBSERVED: compatibility gaps
        |
        v
 [Capsule exporter] -> dependency_exit_capsule.md / .json (observed and AI-generated kept separate)
```

Everything is in one file, `app.py`, built with Streamlit. No database and no server besides Ollama on localhost.

## 5. Dependencies

| Package | Role | License (verify before publishing) |
|---|---|---|
| Streamlit | Web interface | Apache 2.0 |
| ollama (Python client) | Talks to the local Ollama runtime | MIT |
| Ollama (runtime) | Runs Gemma locally | MIT |
| pytest, pip, venv | Used inside the generated test environments | MIT / MIT / PSF |

The tool also analyses **LinkWatch** (https://github.com/rishrek/LinkWatch), the organizer-provided target
repository. It is not included in this repo.

## 6. AI model details

| Field | Value |
|---|---|
| Model name | Gemma 4 |
| Version / tag | `gemma4:e2b` (any installed Gemma 4 tag can be chosen in the sidebar) |
| Source | Ollama model library; weights by Google DeepMind |
| Access method | Local, through the Ollama runtime. No cloud or paid API is used. |
| License / usage terms | Apache 2.0 (confirm on the model page: https://ollama.com/library/gemma4) |
| Role in the project | Writes risk opinions, replacement proposals, migration steps and suggested tests from facts the scanner observed. Its output is labelled AI-generated and is never treated as verified. |

**AI use during development:** an AI coding assistant (Claude) helped write and debug parts of `app.py`.
The team ran and tested the result against LinkWatch. [Edit this line to describe exactly what your team did and verified.]

## 7. Original contribution and disclosures

- Original work, built during the event: the scanner, the evidence-versus-AI separation, the baseline and
  replacement-experiment runner, the conflict check, and the capsule exporter.
- Pre-existing and third-party work: LinkWatch (the target), Streamlit, the Ollama client and runtime, Gemma 4, pytest.
- No API keys, tokens or passwords are used or stored in this repository.

## 8. Known limitations

- The import scan is static. Dynamic imports, transitive use and use outside Python files are not detected.
  "Not imported directly" does not mean "safe to remove".
- Gemma is a small local model. Its output is a suggestion, not a fact, and some answers can be wrong or fail to parse.
- Test results only prove what the repository's existing tests cover.
- Replacement experiments use a mechanical import rewrite and run one dependency at a time. Larger migrations
  (for example pydantic v1 to v2) may need manual code changes, which the tool reports but does not perform.
- Only dependencies with an executed experiment are verified; the rest are suggestions.
- The optional PyPI lookup (internet, off by default) is needed for release-date risk indicators.
- Only `requirements.txt` and `requirements-dev.txt` are read; `pyproject.toml` dependencies are not.
- Security vulnerabilities are deliberately not assessed (out of scope per the organizers).
- Tested end to end on LinkWatch with Python 3.12. [Add: which operating systems you tested on.]
