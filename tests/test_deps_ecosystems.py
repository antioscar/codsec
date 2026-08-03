from __future__ import annotations
import tempfile
import json
from pathlib import Path

from src.deps import scan_manifest, scan_dependencies, collect_manifest_packages


def test_scan_go_mod_vulnerable():
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp, "go.mod")
        p.write_text("module test\nrequire golang.org/x/net v0.20.0\n")
        results = scan_manifest(str(p))
        assert len(results) >= 1
        assert any(r["package"] == "golang.org/x/net" for r in results)


def test_scan_go_mod_safe():
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp, "go.mod")
        p.write_text("module test\nrequire golang.org/x/net v1.5.0\n")
        results = scan_manifest(str(p))
        goto = [r for r in results if r["package"] == "golang.org/x/net"]
        assert len(goto) == 0


def test_scan_gemfile_lock_vulnerable():
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp, "Gemfile.lock")
        p.write_text("GEM\n  remote: https://rubygems.org/\n  specs:\n    actionpack (7.0.0)\n    rack (3.0.0)\n")
        results = scan_manifest(str(p))
        assert len(results) >= 1
        assert any(r["package"] == "actionpack" for r in results)


def test_scan_packages_config_vulnerable():
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp, "packages.config")
        p.write_text('<packages><package id="Newtonsoft.Json" version="12.0.1" /></packages>')
        results = scan_manifest(str(p))
        assert len(results) >= 1
        assert any(r["package"] == "newtonsoft.json" for r in results)


def test_scan_csproj_vulnerable():
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp, "MyProject.csproj")
        p.write_text('<Project><ItemGroup><PackageReference Include="Microsoft.AspNetCore.App" Version="6.0.0" /></ItemGroup></Project>')
        results = scan_manifest(str(p))
        assert len(results) >= 1
        assert any("microsoft.aspnetcore.app" in r["package"] for r in results)


def test_scan_package_lock_vulnerable():
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp, "package-lock.json")
        data = {"packages": {"node_modules/express": {"version": "4.0.0"}}}
        p.write_text(json.dumps(data))
        results = scan_manifest(str(p))
        assert len(results) >= 1
        assert any(r["package"] == "express" for r in results)


def test_scan_yarn_lock_vulnerable():
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp, "yarn.lock")
        p.write_text('express@^4.0.0:\n  version "4.0.0"\n  resolved "..."\n')
        results = scan_manifest(str(p))
        assert len(results) >= 1
        assert any(r["package"] == "express" for r in results)


def test_scan_poetry_lock_vulnerable():
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp, "poetry.lock")
        p.write_text('[[package]]\nname = "django"\nversion = "3.0.0"\n')
        results = scan_manifest(str(p))
        assert len(results) >= 1
        assert any(r["package"] == "django" for r in results)


def test_scan_pipfile_lock_vulnerable():
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp, "Pipfile.lock")
        data = {"default": {"django": {"version": "==3.0.0"}}}
        p.write_text(json.dumps(data))
        results = scan_manifest(str(p))
        assert len(results) >= 1
        assert any(r["package"] == "django" for r in results)


def test_collect_manifest_packages():
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "go.mod").write_text("module t\nrequire golang.org/x/net v1.5.0\n")
        Path(tmp, "Gemfile.lock").write_text("GEM\n  specs:\n    actionpack (7.0.0)\n")
        pkgs = collect_manifest_packages(tmp)
        assert len(pkgs) >= 2
        pkg_names = [p[0] for p in pkgs]
        assert "golang.org/x/net" in pkg_names
        assert "actionpack" in pkg_names


def test_scan_dependencies_new_ecosystems():
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "go.mod").write_text("module t\nrequire golang.org/x/net v0.20.0\n")
        Path(tmp, "packages.config").write_text('<packages><package id="Newtonsoft.Json" version="12.0.1" /></packages>')
        findings = scan_dependencies(tmp)
        assert len(findings) >= 2
        for f in findings:
            assert f.category == "vulnerable_dependency"
