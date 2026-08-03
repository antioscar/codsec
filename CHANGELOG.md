# Changelog

## [1.0.0] - 2025-01-26

### Initial Release

#### Features
- **11 languages**: Python, JavaScript, TypeScript, PHP, Java, Go, C#, Ruby, Kotlin, Swift, Rust
- **28 rule categories** for vulnerability detection
- **Taint analysis**: intra-procedural and inter-procedural data flow tracking
- **Dependency scanning**: 10 manifest formats + online OSV integration (64 CVEs local)
- **Syntax highlighting**: Tree-sitter powered with dark/light theme support
- **Multi-standard compliance**: ISO 27001, ISO 27034, NIST 800-53, OWASP Top 10

#### GUI
- Dashboard with animated KPIs, bar + donut charts, top findings callout
- Findings table with multi-select, context menu, collapsible filters
- Code viewer with syntax highlighting and line highlighting
- Detail panel with copyable remediation and CWE external links
- Compliance tab with per-standard progress bars and JSON export
- Settings panel reorganized into 4 tabs (General, Languages, AI/LLM, Advanced)
- File tree navigator sidebar
- System theme auto-detection (dark/light)
- Toast notifications (non-blocking)
- MRU (Most Recently Used) projects menu
- Keyboard shortcuts (Ctrl+O, Ctrl+R, Ctrl+E, Ctrl+?)
- Quick export button (one-click PDF)
- Cancel confirmation dialog
- About dialog

#### CLI
- PDF, HTML, JSON, SARIF, GitLab Code Quality output formats
- Compliance JSON export
- Baseline comparison (delta findings)
- Exit codes for CI/CD integration
- Custom rules directory support
- Online CVE query (OSV API with 24h cache)
- Parallel scanning (configurable workers)

#### Internationalization (i18n)
- 87 translatable strings via `self.tr()`
- TS template file (Spanish) generated via `pyside6-lupdate`

#### CI/CD
- GitHub Actions CI (Windows + Ubuntu)
- Docker support (Dockerfile + docker-compose with 3 profiles)
- PyInstaller executable bundle

#### Tests
- **292 tests** (287 pass)
- **76% coverage** (src/)
- E2E tests, unit tests, integration tests
