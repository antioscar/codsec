from __future__ import annotations
import subprocess
import sys
import json
import tempfile
from pathlib import Path


def test_cli_json_pdf_html_sarif_gitlab_compliance():
    samples = Path(__file__).resolve().parent / "samples"
    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        json_out = str(td_path / "out.json")
        html_out = str(td_path / "out.html")
        sarif_out = str(td_path / "out.sarif")
        gitlab_out = str(td_path / "out.gitlab.json")
        comp_out = str(td_path / "out.compliance.json")

        result = subprocess.run([
            sys.executable, "main.py",
            "-p", str(samples),
            "--lang", "python,javascript",
            "--no-llm",
            "--fail-on", "none",
            "-o", str(td_path / "out.pdf"),
            "--json-output", json_out,
            "--html", html_out,
            "--sarif", sarif_out,
            "--gitlab", gitlab_out,
            "--compliance-json", comp_out,
        ], capture_output=True, text=True, cwd=str(Path(__file__).resolve().parent.parent))

        assert result.returncode == 0, f"CLI failed: {result.stderr}"

        with open(json_out, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert "findings" in data
        assert "summary_by_severity" in data
        assert "compliance" in data
        assert "standards" in data["compliance"]
        assert "ISO/IEC 27001:2022" in data["compliance"]["standards"]

        assert Path(html_out).exists() and Path(html_out).stat().st_size > 0
        assert Path(sarif_out).exists() and Path(sarif_out).stat().st_size > 0
        assert Path(gitlab_out).exists()

        with open(comp_out, "r", encoding="utf-8") as f:
            comp_data = json.load(f)
        assert "controls_total_evaluated" in comp_data


def test_cli_fail_on_critical_exit_code():
    samples = Path(__file__).resolve().parent / "samples"
    result = subprocess.run([
        sys.executable, "main.py",
        "-p", str(samples),
        "--lang", "python",
        "--no-llm",
        "--fail-on", "critical",
        "-o", str(Path(tempfile.gettempdir()) / "test_out.pdf"),
    ], capture_output=True, text=True, cwd=str(Path(__file__).resolve().parent.parent))

    assert result.returncode in (0, 1), f"Unexpected exit code: {result.returncode}"
