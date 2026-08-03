# AGENTS.md

## Setup

- **Python 3.14+** required. `pip install -r requirements.txt`
- `tree-sitter-typescript==0.23.2` uses `cp39-abi3` wheels — don't upgrade without checking compatibility.

## Commands

```bash
python -m pytest tests/ -v                     # Full suite (208 tests)
python -m pytest tests/test_taint.py -v        # Single file
python -m pytest tests/test_scanner.py::test_scan_parallel_same_results_as_sequential -v  # Single test
```

No linter, typechecker, or formatter configured. No `pyproject.toml` or `setup.py`.

## Entry points

```
python main.py -p <dir> --no-llm              # CLI (click + rich)
python main_gui.py                             # GUI (PySide6)
```

`main.py` line 12 does `sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))` — imports resolve from `src/` dir. The GUI entry works from the project root.

## Architecture

Single-package project with flat layout:

```
main.py / main_gui.py     →  entry points (CLI click, GUI PySide6)
src/
  scanner.py               →  scan_project() is the main orchestrator
  rules/
    engine.py              →  load_rules() + analyze_file() + apply regex + taint + suppression
    taint.py               →  run_taint_analysis() with intra + interprocedural tracking
    parser.py              →  Tree-sitter parsing for 8 languages + _get_language() mapping
  report/
    html_generator.py      →  embedded compliance section
    compliance.py          →  multi-standard evaluation (auto-loads all YAML from config/compliance/)
    json_output.py         →  includes compliance_summary in JSON output
  gui/
    main_window.py         →  QMainWindow with 4 tabs + export toolbar
    compliance_tab.py      →  QTreeWidget with per-standard progress bars
  deps.py                  →  local CVE scan (9 manifest formats) + _version_in_range()
  deps_online.py           →  OSV API client with 24h cache (cache/osv_cache.json)
```

## Config conventions

All config paths use `Path(__file__).resolve().parent.parent.parent / "config" / "..."` — project root is 3 `parent` levels up from `src/`.

| Config | Where loaded |
|--------|-------------|
| `config/settings.yaml` | `src/config.py` — `exclude_dirs`, `min_severity`, `max_workers` |
| `config/sources.yaml` | `src/rules/taint.py` — sources + sinks per language |
| `config/llm.yaml` | `src/llm/provider.py` — `enabled: false` by default (ollama/qwen2.5-coder) |
| `config/rules/*.yaml` | `src/rules/engine.py` — ALL 20 YAMLs loaded, not filtered by `enabled_rules` |
| `config/dependencies/cve_db.yaml` | `src/deps.py` — 37 CVEs, 7 ecosystems |
| `config/compliance/*.yaml` | `src/report/compliance.py` — ALL files auto-loaded, 4 standards |

## Rules system

- `enabled_rules` in `settings.yaml` is **only used by the GUI** (`settings_panel.py`) to populate checkboxes. The engine loads every `.yaml` in `config/rules/`.
- Each rule must have: unique `id`, `category` (snake_case), `severity` (`critical/high/medium/low`), `cwe`, `languages` (from 8 valid ones), and at least one pattern.
- Taint sinks come from BOTH `config/sources.yaml` (per-language `sinks:`) AND `ast_function_names` from loaded rules. The union is `all_sink_names`.
- `severity` validation in `load_rules()` has a fallback: invalid value → `Severity.LOW` with stderr warning.

## Tree-sitter language mapping

In `src/rules/parser.py` `_get_language()`:

| Key | Module |
|-----|--------|
| `python` / `py` | `tree_sitter_python` |
| `javascript` / `js` | `tree_sitter_javascript` |
| `typescript` / `ts` | `tree_sitter_typescript` → `language_typescript()` |
| `tsx` | `tree_sitter_typescript` → `language_tsx()` |
| `php` | `tree_sitter_php` |
| `java` | `tree_sitter_java` |
| `go` | `tree_sitter_go` |
| `csharp` / `c#` / `cs` | `tree_sitter_c_sharp` |
| `ruby` / `rb` | `tree_sitter_ruby` |

## Taint analysis gotchas

- `_build_var_regex` in `taint.py` handles PHP `$var` with `(?<![a-zA-Z0-9_$])` instead of `\b` (word boundary fails before `$`).
- Interprocedural taint: builds function summaries (`param_dangerous`) tracking which param indices flow to sinks. Call sites only flag if the tainted arg position matches a dangerous param index — avoids FP on functions that contain sinks but don't pass params to them.
- `sources.yaml` has `typescript` section at bottom — `run_taint_analysis` falls back to `javascript` config if `typescript` is empty.

## Testing

- GUI tests (`test_gui.py`) use a module-level `qapp` fixture: scoped `module`, reuses `QApplication.instance()`.
- `deps_online.py` tests use `@patch("src.deps_online._query_osv_batch")` etc. — mock at the source module, not where imported (the functions are imported locally inside `scan_project` and `scan_dependencies_online`).
- `test_scanner.py` mocks `src.deps.collect_manifest_packages` and `src.deps_online.scan_dependencies_online` (at source modules, not scanner.py).
- Scanner parallel test: `scan_project(..., max_workers=1)` vs `max_workers=4` — validates deterministic output. Overriding `max_workers` is supported by the `scan_project` signature.
- E2E test (`test_e2e.py`): spawns `subprocess.run([sys.executable, "main.py", ...])` from project root, captures output, asserts JSON files exist.

## PyInstaller

- `analizador.spec` builds `--onedir` with `main.py` as entry.
- Build command: `python -m PyInstaller --clean --noconfirm analizador.spec` (NOT `pyinstaller` CLI — not on PATH).
- Exe at `dist/analizador-seguridad/analizador-seguridad.exe`. Runs CLI scans; `--gui` flag launches GUI via subprocess.
- `os.getcwd()` is used in spec for project root (avoid path encoding issues on Windows).

## Dependencies scan

- Local CVE DB: 37 CVEs in `config/dependencies/cve_db.yaml`, 7 ecosystems (pypi, npm, composer, maven, go, ruby, nuget).
- OSV online (`--online-cve`): queries `api.osv.dev/v1/query`, caches in `cache/osv_cache.json` TTL 24h. `_is_version_affected()` validates installed version against OSV `ranges[].events[]` (introduced/fixed) — does NOT blindly report all vulns.
- Manifest case handling: `Gemfile.lock` and `Pipfile.lock` are lowercased before matching.
- `_parse_version` strips `v` prefix and `^~>=<` operators.

## Git

- Repo en `https://github.com/antioscar/codsec.git`, rama `main`. Para clonar en otra máquina: `git clone https://github.com/antioscar/codsec.git && cd codsec && pip install -r requirements.txt`.
- `.gitignore` incluye: `node_modules/`, `dist/`, `build/`, `cache/`, `.pytest_cache/`, `.coverage`, `__pycache__/`, `*.pyc`, `informe_seguridad.*`.
- El push dispara el CI (`.github/workflows/ci.yml`) que corre los 208 tests con coverage gate ≥75%.

## Roadmap

Ver `ROADMAP.md` para el estado de fases completadas, prioridades futuras y tareas pendientes.

## ISO Compliance

- `src/report/compliance.py` auto-loads all `*.yaml` from `config/compliance/`.
- Evaluates 4 standards: ISO 27001:2022 (8 controls A.8.9–A.8.29), ISO 27034 (13 ASCs), NIST SP 800-53 (SI-10, SC-13, CM-6, SA-11, etc.), OWASP Top 10 (2021).
- Status per control: `compliant` (0 findings) or `non_compliant` (≥1 finding).
- Integrated in: JSON output (auto), HTML report (per-standard tables), GUI (ComplianceTab tree widget), CLI (`--compliance-json`).
