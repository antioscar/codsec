from __future__ import annotations
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional, Callable

from src.discovery import discover_files, detect_languages
from src.models import ScanReport, Severity, Finding
from src.rules.engine import load_rules, analyze_file
from src.deps import scan_dependencies


def scan_project(
    target_path: str,
    languages: Optional[list[str]] = None,
    min_severity: Severity = Severity.LOW,
    exclude_dirs: Optional[set[str]] = None,
    on_progress: Optional[Callable[[int, int, str], None]] = None,
    on_phase: Optional[Callable[[str], None]] = None,
    use_llm: bool = False,
    llm_client=None,
    baseline_path: Optional[str] = None,
    new_only: bool = False,
    online_cve: bool = False,
    rules_dir: Optional[str] = None,
    max_workers: Optional[int] = None,
) -> ScanReport:
    start_time = time.time()

    files = discover_files(target_path, languages=languages, exclude_dirs=exclude_dirs)
    total_files = len(files)

    rules = load_rules(rules_dir)
    from src.discovery import language_from_extension

    from src.config import load_config
    config = load_config()
    if max_workers is None:
        max_workers = config.get("max_workers", 4)

    analysable: list[tuple[int, str, str]] = []
    for idx, file_path in enumerate(files, 1):
        language = language_from_extension(file_path)
        if language is not None:
            analysable.append((idx, file_path, language))

    if on_phase:
        on_phase("rules")

    all_findings: list[Finding] = []
    progress_lock = threading.Lock()
    progress_count = [0]

    def _analyze_file(args: tuple[int, str, str]) -> tuple[int, list[Finding]]:
        idx, file_path, language = args
        try:
            findings = analyze_file(file_path, language, rules)
        except Exception:
            findings = []
        with progress_lock:
            progress_count[0] += 1
            if on_progress:
                on_progress(progress_count[0], len(analysable), file_path)
        return idx, findings

    if analysable and max_workers > 1:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_map = {executor.submit(_analyze_file, a): a for a in analysable}
            results_by_idx: dict[int, list[Finding]] = {}
            for future in as_completed(future_map):
                idx, findings = future.result()
                results_by_idx[idx] = findings
        for idx in sorted(results_by_idx):
            all_findings.extend(results_by_idx[idx])
    else:
        for idx, file_path, language in analysable:
            _, file_findings = _analyze_file((idx, file_path, language))
            all_findings.extend(file_findings)

    counter = 0
    for f in all_findings:
        counter += 1
        f.id = f"{f.category[:4].upper()}-{counter:04d}"

    dep_findings = scan_dependencies(target_path)

    if on_phase:
        on_phase("deps")

    if online_cve:
        try:
            if on_progress:
                on_progress(0, 1, "Consulta de CVE online (OSV)...")
            from src.deps_online import scan_dependencies_online
            from src.deps import collect_manifest_packages
            online_pkgs = collect_manifest_packages(target_path)
            online_results = scan_dependencies_online(target_path, online_pkgs) if online_pkgs else []
            existing_cves = set()
            for df in dep_findings:
                desc = df.description
                cve_match = None
                for word in desc.split():
                    if word.startswith("CVE-"):
                        cve_match = word.rstrip(":")
                        break
                if cve_match:
                    existing_cves.add(cve_match)
            for r in online_results:
                if r.get("cve") in existing_cves:
                    continue
                sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM, "low": Severity.LOW}
                sev = sev_map.get(r.get("severity", "medium"), Severity.MEDIUM)
                dep_findings.append(Finding(
                    id="",
                    category="vulnerable_dependency",
                    severity=sev,
                    cwe="CWE-1104",
                    language="",
                    file_path=target_path,
                    line_number=0,
                    code_snippet="",
                    description=f"Dependencia vulnerable: {r['package']}@{r['version']} — {r['cve']}: {r['description']}",
                    remediation=f"Actualizá {r['package']} a la versión {r.get('fixed', 'más reciente')}.",
                    confidence="medium",
                ))
        except Exception:
            pass

    for df in dep_findings:
        counter += 1
        df.id = f"DEPS-{counter:04d}"
        all_findings.append(df)

    if use_llm:
        if on_phase:
            on_phase("llm")
        all_findings = _run_llm_phase(
            target_path, files, all_findings, counter, llm_client, on_progress
        )

    if baseline_path:
        if on_phase:
            on_phase("baseline")
        from src.baseline import load_baseline, mark_findings, filter_new
        baseline = load_baseline(baseline_path)
        mark_findings(all_findings, baseline)
        if new_only:
            all_findings = filter_new(all_findings)
        if on_progress:
            new_count = sum(1 for f in all_findings if f.is_new)
            exist_count = sum(1 for f in all_findings if not f.is_new)
            on_progress(0, 1, f"Baseline: {new_count} nuevos, {exist_count} existentes")

    filtered = [f for f in all_findings if f.severity.order <= min_severity.order]

    elapsed = time.time() - start_time

    return ScanReport(
        target_path=target_path,
        total_files_scanned=total_files,
        total_findings=len(filtered),
        findings=filtered,
        scan_duration_seconds=round(elapsed, 2),
    )


def _run_llm_phase(
    target_path: str,
    files: list[str],
    all_findings: list[Finding],
    counter: int,
    llm_client,
    on_progress: Optional[Callable[[int, int, str], None]] = None,
) -> list[Finding]:
    from src.llm.provider import (
        load_llm_config, get_features, get_llm_caps, LLMClient,
    )
    from src.llm.verifier import verify_findings, apply_verdicts
    from src.llm.semantic import semantic_scan
    from src.llm.remediation import enhance_all_remediations

    if llm_client is None:
        config = load_llm_config()
        llm_client = LLMClient(config)

    try:
        features = get_features()
        caps = get_llm_caps()

        if features.get("verify", True):
            if on_progress:
                on_progress(0, 1, "Verificación IA de hallazgos...")
            verdicts = verify_findings(
                all_findings, llm_client,
                max_findings=caps.get("max_verify_findings", 30),
                on_progress=on_progress,
            )
            all_findings = apply_verdicts(all_findings, verdicts)

        if features.get("semantic", True):
            if on_progress:
                on_progress(0, 1, "Análisis semántico IA...")
            sem_findings = semantic_scan(
                files, llm_client,
                max_files=caps.get("max_semantic_files", 20),
                on_progress=on_progress,
            )
            for sf in sem_findings:
                counter += 1
                sf.id = f"AI-SEM-{counter:04d}"
                all_findings.append(sf)

        if features.get("remediation", True):
            if on_progress:
                on_progress(0, 1, "Mejora de remediación IA...")
            enhance_all_remediations(
                all_findings, llm_client,
                on_progress=on_progress,
            )
    finally:
        try:
            llm_client.close()
        except Exception:
            pass

    return all_findings
