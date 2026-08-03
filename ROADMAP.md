# Roadmap

## Fases completadas

| Fase | Contenido | Tests |
|------|----------|-------|
| A | Scanner base, 13 categorías de reglas, taint básico, CLI, PDF | ~53 |
| B | Reglas custom, config YAML, 8 lenguajes, deps CVE, LLM | ~70 |
| C | GUI (PySide6), HTML/SARIF/outputs, suppression, coverage | ~110 |
| D | Baseline, discover, LLM verify/semantic | ~125 |
| E | E2E, custom rules dir, deps ecosystems, CI infra | ~149 |
| F | Paralelismo, taint interprocedimental, 7 reglas nuevas (→20), PyInstaller, compliance ISO 27001 | ~167 |
| G | Tests deps_online, compliance multi-estándar, GUI ComplianceTab, CI GitHub Actions | **208** |
| H | GUI polish (temas, empty states, QSettings, atajos, iconos), README showcase, ROADMAP.md | 208 |
| I | GUI 2.0 (dashboard redesign, toast notifications, file tree navigator, multi-select, shortcut help, collapsible filters, settings tabs, detail panel enrich, export 1-click, theme contrast) | 279 |

## Estado actual (Fase H completada)

- **279 tests pasando**, 81% coverage (gate CI ≥75%)
- 20 categorías de reglas, 4 estándares de compliance, 11 lenguajes (Kotlin, Swift, Rust)
- GUI con temas oscuro/claro responsivos, QSettings, atajos de teclado, empty states
- Exe PyInstaller (`dist/analizador-seguridad/analizador-seguridad.exe`)
- CI en GitHub Actions (Windows + Ubuntu)

## Prioridades futuras

### Alta
- [x] i18n: extraer todos los strings hardcodeados a `self.tr()` + generar `.ts` (i18n/codsec_es.ts, 87 strings)
- [x] Syntax highlighting en el CodeViewer (tree-sitter)
- [x] Soporte para más lenguajes (Kotlin, Swift, Rust)
- [x] Mejorar coverage a ≥80% (cubrir paths de LLM y GUI no testeados)

### Media
- [x] Auto-detección de tema del sistema (`QStyleHints.colorScheme()`)
- [x] Menú de proyectos recientes (MRU en QSettings)
- [x] Progress granular por fase (parsing → reglas → taint → deps → LLM)
- [x] Exportación de compliance desde la pestaña GUI
- [x] About dialog con versión y créditos
- [x] Cancelar con confirmación (dialog al cancelar escaneo)

### Baja
- [ ] Tests del path LLM en scanner (hoy mockeado, falta integración real)
- [ ] Soporte para más formatos de manifiesto de dependencias
- [ ] Docker image para CI/CD fácil
- [ ] Changelog y versionado semántico
- [ ] Video demo / GIF animado para el README

## Convenciones del proyecto

Ver `AGENTS.md` para detalles técnicos de setup, arquitectura, testing y gotchas.
