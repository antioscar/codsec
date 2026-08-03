from __future__ import annotations
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

from src.scanner import scan_project, _run_llm_phase
from src.models import Severity


def test_scan_project_basic():
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "app.py").write_text('API_KEY = "sk-1234567890abcdef1234567890abcdef"\neval("1+1")')
        Path(tmp, "util.js").write_text('document.body.innerHTML = data;')

        report = scan_project(tmp, languages=["python", "javascript"], min_severity=Severity.LOW)
        assert report.total_files_scanned == 2
        assert report.total_findings >= 3
        assert report.scan_duration_seconds >= 0
        assert report.target_path == tmp


def test_scan_project_filter_severity():
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "app.py").write_text('API_KEY = "sk-1234567890abcdef1234567890abcdef"')
        Path(tmp, "test.py").write_text('import hashlib; hashlib.md5(b"x")')

        report = scan_project(tmp, min_severity=Severity.HIGH)
        for f in report.findings:
            assert f.severity.order <= Severity.HIGH.order


def test_scan_project_progress_callback():
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "a.py").write_text('x = 1')
        Path(tmp, "b.py").write_text('y = 2')

        progress_log = []

        def on_progress(current, total, file_path):
            progress_log.append((current, total, file_path))

        report = scan_project(tmp, on_progress=on_progress)
        assert len(progress_log) == 2
        assert progress_log[0][0] == 1
        assert progress_log[1][0] == 2


def test_scan_project_no_files():
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "readme.md").write_text("# hello")
        report = scan_project(tmp)
        assert report.total_files_scanned == 0
        assert report.total_findings == 0


def test_scan_parallel_same_results_as_sequential():
    with tempfile.TemporaryDirectory() as tmp:
        for i in range(10):
            Path(tmp, f"file_{i}.py").write_text(
                'import os\n'
                f'from flask import request\n'
                f'def handler_{i}():\n'
                f'    val_{i} = request.args.get("x")\n'
                f'    os.system(val_{i})\n'
            )

        report_sequential = scan_project(tmp, languages=["python"], max_workers=1)
        report_parallel = scan_project(tmp, languages=["python"], max_workers=4)

        assert report_sequential.total_findings == report_parallel.total_findings

        seq_ids = sorted(f.id for f in report_sequential.findings)
        par_ids = sorted(f.id for f in report_parallel.findings)
        assert seq_ids == par_ids

        seq_cats = {(f.file_path, f.category, f.line_number) for f in report_sequential.findings}
        par_cats = {(f.file_path, f.category, f.line_number) for f in report_parallel.findings}
        assert seq_cats == par_cats


@patch("src.deps.collect_manifest_packages")
@patch("src.deps_online.scan_dependencies_online")
def test_scan_online_cve_merge_dedupe(mock_online, mock_collect):
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "app.py").write_text("x = 1")

        mock_collect.return_value = [("requests", "2.28.0", "pypi")]
        mock_online.return_value = [
            {
                "package": "requests",
                "version": "2.28.0",
                "cve": "CVE-2024-9999",
                "severity": "high",
                "description": "New vuln found online",
                "fixed": "2.29.0",
                "ecosystem": "PyPI",
            },
        ]

        report = scan_project(tmp, languages=["python"], online_cve=True)

        online_findings = [f for f in report.findings if "CVE-2024-9999" in f.description]
        assert len(online_findings) == 1


@patch("src.deps.collect_manifest_packages")
@patch("src.deps_online.scan_dependencies_online")
def test_scan_online_cve_no_duplicate_local(mock_online, mock_collect):
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "app.py").write_text("x = 1")

        mock_collect.return_value = [("flask", "2.0.0", "pypi")]
        mock_online.return_value = [
            {
                "package": "flask",
                "version": "2.0.0",
                "cve": "CVE-2023-30861",
                "severity": "high",
                "description": "Already in local DB",
                "fixed": "2.2.5",
                "ecosystem": "PyPI",
            },
        ]

        report = scan_project(tmp, languages=["python"], online_cve=True)
        online_dupes = [f for f in report.findings if "CVE-2023-30861" in f.description and "Online" not in f.description]
        assert len(online_dupes) <= 1


def test_scan_with_phase_callbacks():
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "app.py").write_text('x = 1')
        phases = []

        def on_phase(phase):
            phases.append(phase)

        report = scan_project(tmp, on_phase=on_phase)
        assert "rules" in phases
        assert "deps" in phases
        assert report.total_files_scanned == 1


@patch("src.deps_online.scan_dependencies_online")
@patch("src.deps.collect_manifest_packages")
def test_scan_online_cve_error_swallowed(mock_collect, mock_online):
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "app.py").write_text("x = 1")
        mock_collect.return_value = [("requests", "2.28.0", "pypi")]
        mock_online.side_effect = Exception("API down")

        report = scan_project(tmp, languages=["python"], online_cve=True)
        assert report is not None
        assert report.total_files_scanned == 1


@patch("src.deps_online.scan_dependencies_online")
@patch("src.deps.collect_manifest_packages")
@patch("src.deps.scan_dependencies")
def test_scan_online_cve_dedupe(mock_deps, mock_collect, mock_online):
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "app.py").write_text("x = 1")

        mock_deps.return_value = []
        mock_collect.return_value = [("lib", "1.0.0", "pypi")]
        mock_online.return_value = [
            {
                "package": "lib",
                "version": "1.0.0",
                "cve": "CVE-2024-1234",
                "severity": "high",
                "description": "RCE vuln",
                "fixed": "2.0.0",
                "ecosystem": "PyPI",
            },
        ]

        from src.models import Finding
        dep_findings = [
            Finding(
                id="DEPS-0001", category="vulnerable_dependency",
                severity=Severity.HIGH, cwe="CWE-1104", language="",
                file_path=tmp, line_number=0, code_snippet="",
                description="Dependencia vulnerable: CVE-2024-1234: some vuln",
                remediation="Update", confidence="medium",
            )
        ]
        mock_deps.return_value = dep_findings

        report = scan_project(tmp, languages=["python"], online_cve=True)
        cve_count = sum(1 for f in report.findings if "CVE-2024-1234" in f.description)
        assert cve_count == 1


def test_scan_with_baseline_phase():
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "app.py").write_text("x = 1")

        import json
        baseline_data = {
            "findings": [
                {"file_path": str(Path(tmp, "app.py")), "category": "hardcoded_secrets", "line_number": 1}
            ]
        }
        baseline_path = str(Path(tmp, "baseline.json"))
        with open(baseline_path, "w") as f:
            json.dump(baseline_data, f)

        phases = []
        progress_msgs = []

        def on_phase(phase):
            phases.append(phase)

        def on_progress(current, total, msg):
            progress_msgs.append(msg)

        report = scan_project(tmp, baseline_path=baseline_path, on_phase=on_phase, on_progress=on_progress)
        assert "baseline" in phases
        assert report is not None


@patch("src.deps.collect_manifest_packages")
def test_scan_online_cve_progress_message(mock_collect):
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "app.py").write_text("x = 1")
        mock_collect.return_value = []

        progress_msgs = []

        def on_progress(current, total, msg):
            progress_msgs.append(msg)

        report = scan_project(tmp, languages=["python"], online_cve=True, on_progress=on_progress)
        assert any("Consulta de CVE online (OSV)" in str(m) for m in progress_msgs)


@patch("src.llm.provider.get_features", return_value={})
@patch("src.llm.verifier.verify_findings", return_value={})
@patch("src.llm.provider.LLMClient")
@patch("src.llm.provider.load_llm_config")
def test_run_llm_phase_creates_client(mock_load_config, mock_llm_client_class, mock_verify, mock_features):
    mock_load_config.return_value = {"provider": "ollama", "model": "test"}
    mock_client = MagicMock()
    mock_llm_client_class.return_value = mock_client

    _run_llm_phase("/tmp", [], [], 0, llm_client=None)

    mock_llm_client_class.assert_called_once()


@patch("src.llm.provider.get_features", return_value={})
@patch("src.llm.verifier.verify_findings", return_value={})
@patch("src.llm.provider.LLMClient")
@patch("src.llm.provider.load_llm_config")
def test_run_llm_phase_close_error_swallowed(mock_load_config, mock_llm_client_class, mock_verify, mock_features):
    mock_load_config.return_value = {"provider": "ollama", "model": "test"}
    mock_client = MagicMock()
    mock_client.close.side_effect = Exception("Close failed")
    mock_llm_client_class.return_value = mock_client

    result = _run_llm_phase("/tmp", [], [], 0, llm_client=None)

    assert result is not None


def test_scan_error_in_analyze_file_swallowed():
    import tempfile
    from pathlib import Path
    from src.scanner import scan_project
    from src.models import Severity
    phases = []
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "app.py").write_text("x=1")
        report = scan_project(tmp, languages=["python"], min_severity=Severity.LOW, on_phase=lambda p: phases.append(p))
    assert "rules" in phases


@patch("src.deps.collect_manifest_packages")
@patch("src.deps_online.scan_dependencies_online")
def test_scan_online_cve_exception_swallowed(mock_online, mock_collect):
    import tempfile
    from pathlib import Path
    from src.scanner import scan_project
    from src.models import Severity
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "app.py").write_text("x=1")
        mock_collect.return_value = [("requests", "2.28.0", "pypi")]
        mock_online.side_effect = Exception("network error")
        report = scan_project(tmp, languages=["python"], min_severity=Severity.LOW, online_cve=True)
    assert report is not None
