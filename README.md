# Analizador de Seguridad de Código

[![CI](https://github.com/antioscar/codsec/actions/workflows/ci.yml/badge.svg)](https://github.com/antioscar/codsec/actions/workflows/ci.yml)
[![Python 3.14+](https://img.shields.io/badge/python-3.14+-blue.svg)](https://www.python.org/downloads/)
[![Tests](https://img.shields.io/badge/tests-279%20passed-brightgreen.svg)](https://github.com/antioscar/codsec)
[![Coverage](https://img.shields.io/badge/coverage-81%25-green.svg)](https://github.com/antioscar/codsec)

Herramienta de análisis estático de seguridad (SAST) para webapps con escaneo paralelo. Escanea código fuente en Python, JavaScript, TypeScript, PHP, Java, Go, C#, Ruby, Kotlin, Swift y Rust mediante 20 categorías de reglas + análisis de taint (intra e interprocedimental) + dependencias vulnerables (9 formatos, consulta online OSV opcional), e integra inteligencia artificial (LLM) opcional. Incluye reporte de cumplimiento multi-estándar (ISO 27001:2022, ISO 27034, NIST SP 800-53, OWASP Top 10). Genera informes en PDF, HTML, JSON, SARIF, GitLab Code Quality y cumplimiento ISO. Distribuible como ejecutable único con PyInstaller.

**Incluye interfaz gráfica (GUI)** y línea de comandos (CLI).

## Requisitos

- Python 3.14+
- `pip install -r requirements.txt`

## Quickstart

```bash
git clone https://github.com/antioscar/codsec.git
cd codsec
pip install -r requirements.txt
python main.py -p tests/samples --no-llm -o demo.pdf
```

Esto escanea los samples incluidos y genera `demo.pdf`. Para ejecutar la GUI: `python main_gui.py`.

## Uso

### Interfaz gráfica (GUI)

```bash
python main_gui.py
```

**Pestañas:**
- Dashboard con KPIs animados, gráfico de barras + donut, top findings y stats rápidos
- Tabla de hallazgos con multi-selección, menú contextual y filtros colapsables
- Visor de código con syntax highlighting y línea afectada resaltada
- Detalle con descripción, remediación copiable y enlace CWE externo
- Cumplimiento multi-estándar con exportación JSON integrada
- Configuración reorganizada en 4 pestañas (General, Lenguajes, IA/LLM, Avanzado)
- File tree navigator lateral con árbol de archivos del proyecto
- Tema oscuro / claro con auto-detección del sistema y estilos refinados
- Toast notifications no bloqueantes para acciones exitosas
- Exportación: PDF, HTML, SARIF, cumplimiento JSON + export rápido toolbar (Ctrl+E para PDF)
- Atajos: `Ctrl+O` seleccionar carpeta, `Ctrl+R` analizar, `Ctrl+E` exportar PDF, `Ctrl+?` ayuda
- Proyectos recientes con menú desplegable en la toolbar
- Progreso granular por fase (Reglas → Dependencias → IA)
- Diálogo de confirmación al cancelar escaneo
- Acerca de con versión y créditos
- Persistencia de configuración: última carpeta, geometría de ventana, tema y proyectos recientes

> **Tip:** Generá screenshots con la GUI sobre `tests/samples` para tu portafolio. Las 4 pestañas con resultados muestran todo el producto.

### Línea de comandos (CLI)

El escaneo usa paralelismo automático (`max_workers: 4` en `config/settings.yaml`).

```bash
python main.py -p <ruta_del_proyecto> -o <informe.pdf>
```

### Opciones CLI

| Flag | Descripción |
|------|------------|
| `-p, --path` | Ruta del proyecto a analizar (default: `.`) |
| `-o, --output` | Archivo PDF de salida (default: `informe_seguridad.pdf`) |
| `-j, --json-output` | Archivo JSON de salida intermedia |
| `-l, --lang` | Lenguajes separados por coma (ej: `python,js,go`) |
| `-s, --min-severity` | Severidad mínima: `critical`, `high`, `medium`, `low` (default: `low`) |
| `-e, --exclude` | Directorios adicionales a excluir |
| `--llm / --no-llm` | Habilitar/deshabilitar análisis con IA (sobrescribe config) |
| `--baseline <json>` | Archivo JSON de baseline para comparación delta |
| `--new-only` | Mostrar solo hallazgos nuevos (requiere --baseline) |
| `--html <archivo>` | Archivo HTML de salida |
| `--sarif <archivo>` | Archivo SARIF de salida (v2.1.0) |
| `--gitlab <archivo>` | Archivo GitLab Code Quality de salida |
| `--compliance-json <archivo>` | Archivo JSON de cumplimiento ISO 27001:2022 |
| `--online-cve` | Consultar CVE online (OSV) además de la base local |
| `--rules-dir <dir>` | Directorio con reglas YAML personalizadas |
| `--fail-on <sev>` | Exit code 1 si hay hallazgos ≥ severidad (critical, high, medium, low, none; default: high) |

### Ejemplos

```bash
# Demo rápido (scan de tests/samples incluidos)
python main.py -p tests/samples --no-llm -o demo.pdf

# Analizar todo el proyecto
python main.py -p ./mi_app -o informe.pdf

# Solo Python y JS, con salida JSON y PDF
python main.py -p ./mi_app -o informe.pdf -j informe.json -l python,js

# Ignorar critical y high, excluir directorios extra
python main.py -p ./mi_app -o informe.pdf -s medium -e migrations,tests

# Activar análisis con IA
python main.py -p ./mi_app -o informe.pdf --llm
```

## Categorías de fallas detectadas

### Reglas estáticas

| Categoría | CWE | Severidad |
|-----------|-----|-----------|
| SQL Injection | CWE-89 | Crítica |
| Command Injection | CWE-78 | Crítica |
| Hardcoded Secrets | CWE-798 | Crítica |
| XSS | CWE-79 | Alta |
| Path Traversal | CWE-22 | Alta |
| SSRF | CWE-918 | Alta |
| Insecure Deserialization | CWE-502 | Alta |
| Dynamic Code Execution | CWE-95 | Alta |
| Insecure Cryptography | CWE-327 | Media |
| Open Redirect | CWE-601 | Alta |
| CSRF | CWE-352 | Alta |
| Security Headers / Debug | CWE-693 | Media |
| Information Disclosure | CWE-209 | Media |
| SSTI (Template Injection) | CWE-1336 | Crítica |
| XXE (XML External Entity) | CWE-611 | Crítica |
| LDAP Injection | CWE-90 | Alta |
| Prototype Pollution | CWE-1321 | Alta |
| Log Injection | CWE-117 | Media |
| Zip-Slip | CWE-22 | Alta |
| Weak Hash (MD5/SHA1) | CWE-328 | Alta |

### Dependencias vulnerables

| Ecosistema | Archivos analizados |
|------------|-------------------|
| Python (pip) | `requirements.txt`, `poetry.lock`, `Pipfile.lock` |
| JavaScript (npm) | `package.json`, `package-lock.json`, `yarn.lock` |
| PHP (composer) | `composer.json`, `composer.lock` |
| Java (maven) | `pom.xml` |
| Go | `go.mod` | 
| Ruby | `Gemfile.lock` |
| NuGet (C#/.NET) | `packages.config`, `*.csproj` |

### Consulta online OSV (opcional)

Con el flag `--online-cve` (CLI) o activando la casilla en la GUI, se consulta la API de OSV (`api.osv.dev`) para obtener CVEs actualizados. Los resultados se cachean localmente por 24h (`cache/osv_cache.json`). Requiere conexión a internet.

### Análisis de taint (flujo de datos)

Rastrea datos de fuentes de usuario (request, input, $_GET, etc.) hacia funciones peligrosas (execute, eval, etc.), elevando la confianza de los hallazgos a `high`. Incluye análisis interprocedimental que detecta wrappers de funciones peligrosas dentro del mismo archivo.

## Integración con IA (LLM) — opcional

La herramienta puede usar un LLM local (Ollama) o remoto (OpenAI-compatible) para tres tareas:

1. **Verificación de hallazgos**: confirma o descarta falsos positivos, ajustando la confianza.
2. **Análisis semántico**: busca vulnerabilidades no cubiertas por reglas estáticas (SSTI, IDOR, XXE, lógica de negocio, etc.).
3. **Mejora de remediación**: genera pasos específicos y detallados para cada hallazgo.

### Configuración

Editar `config/llm.yaml`:

```yaml
provider: ollama              # ollama | openai_compatible
base_url: http://localhost:11434
model: qwen2.5-coder

openai_compatible:
  base_url: https://api.openai.com/v1
  model: gpt-4o-mini
  api_key_env: OPENAI_API_KEY

features:
  verify: true
  semantic: true
  remediation: true

enabled: false                 # true = IA siempre activa en el escaneo
max_verify_findings: 30
max_semantic_files: 20
```

- **Ollama**: sin API key. Instalar [Ollama](https://ollama.com) y ejecutar `ollama pull qwen2.5-coder`.
- **OpenAI-compatible**: funciona con OpenAI, OpenRouter, Groq, LM Studio, vLLM. Configurar `api_key_env` con el nombre de la variable de entorno de la API key.

La configuración también se puede ajustar desde la GUI (pestaña Configuración → sección IA/LLM).

## Lenguajes soportados

- Python (`.py`) — reglas + AST + taint
- JavaScript (`.js`, `.mjs`, `.cjs`) — reglas + AST + taint
- TypeScript (`.ts`, `.tsx`, `.mts`, `.cts`) — reglas + AST + taint
- PHP (`.php`, `.phtml`) — reglas + AST + taint
- Java (`.java`, `.jsp`) — reglas + AST + taint
- Go (`.go`) — reglas + AST + taint
- C# (`.cs`) — reglas + AST + taint
- Ruby (`.rb`) — reglas + AST + taint
- Kotlin (`.kt`, `.kts`) — reglas + AST + taint
- Swift (`.swift`) — reglas + AST + taint
- Rust (`.rs`) — reglas + AST + taint

## Cómo agregar una regla nueva

Crear un archivo YAML en `config/rules/`:

```yaml
id: RULE-001
category: nombre_categoria
severity: high
cwe: "CWE-XXX"
description_template: "Descripción de la falla detectada"
remediation: |
  1. Paso de remediación.
  2. Otro paso.
languages: [python, javascript, typescript, php, java]
ast_function_names: [funcion_peligrosa]
regex_patterns:
  - '(?i)patron\s+regex\s*\('
```

Los campos:
- `id`: identificador único
- `category`: categoría (snake_case)
- `severity`: `critical`, `high`, `medium`, `low`
- `cwe`: referencia CWE
- `description_template`: mensaje para el hallazgo
- `remediation`: pasos de remediación (una línea por paso con `1.`, `2.`, etc.)
- `languages`: lenguajes donde aplica
- `ast_function_names`: nombres de funciones a detectar en el AST
- `regex_patterns`: patrones regex para detectar en el código fuente

## Estructura del proyecto

```
├── main.py                  # CLI (Click + Rich) + --gui flag
├── main_gui.py              # GUI (PySide6) — python main_gui.py
├── requirements.txt
├── analizador.spec          # Spec de PyInstaller
├── build_exe.ps1            # Script de construcción del exe
├── .github/workflows/
│   └── ci.yml               # CI: tests + coverage + self-scan + build
├── hooks/
│   └── pre-commit           # Ejemplo de hook pre-commit
├── config/
│   ├── rules/               # Reglas YAML editables (20 categorías)
│   ├── settings.yaml        # Configuración global + paralelismo (max_workers)
│   ├── sources.yaml         # Fuentes/sinks para taint analysis (8 lenguajes)
│   ├── llm.yaml             # Configuración de IA/LLM
│   ├── compliance/
│   │   ├── iso27001.yaml     # Mapeo categorías → ISO 27001 + OWASP Top 10
│   │   ├── iso27034.yaml     # Mapeo → ISO/IEC 27034
│   │   └── nist80053.yaml    # Mapeo → NIST SP 800-53
│   └── dependencies/
│       └── cve_db.yaml       # Base local de CVEs (37 CVEs, 7 ecosistemas)
├── src/
│   ├── main.py              # Comando scan (CLI)
│   ├── scanner.py           # Motor de escaneo reutilizable (CLI + GUI)
│   ├── config.py            # Carga de config global
│   ├── deps.py              # Escáner de dependencias (9 formatos de manifiesto)
│   ├── deps_online.py       # Consulta OSV online con cache
│   ├── baseline.py          # Baseline/delta de hallazgos
│   ├── models.py            # Finding, Severity, ScanReport, Rule
│   ├── discovery.py         # Descubrimiento de archivos
│   ├── rules/
│   │   ├── engine.py        # Motor de reglas + integración taint + supresión
│   │   ├── parser.py        # Tree-sitter 11 lenguajes + mask_comments
│   │   ├── regex_rules.py   # Aplicación de regex + heurísticas FP
│   │   ├── taint.py         # Análisis de flujo de datos (intra + interprocedimental)
│   │   └── suppression.py   # Supresión nosemgrep
│   ├── report/
│   │   ├── pdf_generator.py # PDF con reportlab
│   │   ├── json_output.py   # Salida JSON
│   │   ├── html_generator.py # HTML autocontenido con tema oscuro
│   │   ├── sarif_output.py  # SARIF v2.1.0
│   │   ├── gitlab_output.py # GitLab Code Quality
│   │   └── compliance.py    # Evaluación de cumplimiento ISO 27001:2022
│   ├── gui/
│   │   ├── app.py           # QApplication + theme
│   │   ├── main_window.py   # QMainWindow: toolbar + tabs + export
│   │   ├── themes.py        # QSS dark/light
│   │   ├── scan_worker.py   # QThread background scan + phase signals
│   │   ├── dashboard.py     # Resumen + gráfico de barras
│   │   ├── findings_table.py # Tabla filtrable + visor + detalle
│   │   ├── code_viewer.py   # Visor con syntax highlighting y números de línea
│   │   ├── settings_panel.py # Config persistente + IA/LLM + baseline + reglas
│   │   └── compliance_tab.py # Pestaña de cumplimiento multi-estándar
│   └── llm/
│       ├── provider.py      # Cliente LLM (Ollama + OpenAI-compatible)
│       ├── parsing.py       # Parseo robusto de JSON
│       ├── verifier.py      # Verificación de hallazgos con IA
│       ├── semantic.py      # Análisis semántico libre
│       └── remediation.py   # Mejora de remediación con IA
└── tests/
    ├── samples/             # Código vulnerable (11 lenguajes)
    └── test_*.py            # 279 tests
```

## Cumplimiento ISO 27001:2022

La herramienta evalúa automáticamente el cumplimiento contra múltiples estándares: **ISO/IEC 27001:2022**, **ISO/IEC 27034**, **NIST SP 800-53** y **OWASP Top 10 (2021)**. Cada hallazgo se mapea a controles de cada estándar.

| Control | Título | Categorías cubiertas |
|---|---|---|
| A.8.9 | Gestión de configuración | secrets, security_headers |
| A.8.24 | Uso de criptografía | insecure_crypto, weak_hash |
| A.8.25 | Ciclo de vida de desarrollo seguro | insecure_deserialization, vulnerable_dependency |
| A.8.26 | Requisitos de seguridad | open_redirect, csrf, xss, sql_injection, info_disclosure |
| A.8.27 | Arquitectura segura | ssrf |
| A.8.28 | Codificación segura | Las 20 categorías |
| A.8.29 | Pruebas de seguridad | injection, traversal, ssti, xxe, etc. |

El reporte HTML incluye una tabla de cumplimiento por estándar con estado (cumplido/incumplido) y porcentaje. La GUI incluye una pestaña "Cumplimiento" con árbol de controles y barras de progreso por estándar.

### OWASP Top 10 / ISO 27034 / NIST 800-53

Además de ISO 27001, se mapean automáticamente: OWASP Top 10 (2021): A01-A10, ISO/IEC 27034 (13 controles de aplicación), y NIST SP 800-53 (SI-10, SC-13, CM-6, SA-11, etc.). El JSON de cumplimiento incluye todos los estándares:

```bash
python main.py -p . --compliance-json compliance.json --no-llm
```

## Integración CI/CD

### Exit codes

El CLI retorna exit codes según el flag `--fail-on`:
- `0` sin hallazgos (o `--fail-on none`)
- `1` hay hallazgos ≥ umbral de severidad
- `2` error de ejecución

```bash
python main.py -p . --fail-on high    # exit 1 si hay hallazgos high o critical
python main.py -p . --fail-on none    # siempre exit 0
```

### GitHub Actions

```yaml
- uses: actions/upload-sarif@v4
  with:
    sarif_file: informe.sarif
```

### GitLab CI

```yaml
artifacts:
  reports:
    codequality: gl-code-quality.json
```

## Empaquetado (PyInstaller)

Genera un ejecutable autocontenido con PyInstaller (modo `--onedir`):

```bash
.\build_exe.ps1                  # Ejecutar desde raíz del proyecto
dist\analizador-seguridad\analizador-seguridad.exe -p . --no-llm
```

El ejecutable incluye CLI (`main.py`) con todos los flags. Para GUI usar `python main_gui.py` desde fuente.

## CI/CD del proyecto

El proyecto incluye su propio pipeline en `.github/workflows/ci.yml`:
- Tests con coverage gate ≥75% (Windows + Ubuntu)
- Self-scan (analizador sobre `src/`)
- Build del exe con PyInstaller (Windows)
- Artefacto del exe descargable

## Pre-commit hook

Ejemplo en `hooks/pre-commit`:
```bash
python main.py -p . --fail-on high --no-llm
```

## Tests

```bash
python -m pytest tests/ -v
```

279 tests cubriendo: reglas (20 categorías), AST, taint (intra + interprocedimental), dependencias (9 formatos + OSV online, +36 tests deps_online), IA/LLM (+23 tests provider/verifier/semantic/remediation/parsing), PDF, HTML, JSON, SARIF, GitLab Code Quality, compliance multi-estándar (ISO 27001, ISO 27034, NIST 800-53, OWASP Top 10), baseline, supresión, reglas personalizadas, exit codes CI/CD, e2e, GUI (35 tests), 11 lenguajes (Kotlin, Swift, Rust).
