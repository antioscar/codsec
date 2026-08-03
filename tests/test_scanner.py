from __future__ import annotations
import tempfile
from pathlib import Path
from unittest.mock import patch

from src.scanner import scan_project
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
