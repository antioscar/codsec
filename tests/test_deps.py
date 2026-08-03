from __future__ import annotations
import tempfile
import json
from pathlib import Path

from src.deps import scan_manifest, scan_dependencies, _version_in_range, _parse_version


def test_parse_version():
    assert _parse_version("1.2.3") == (1, 2, 3)
    assert _parse_version("^1.0") == (1, 0)
    assert _parse_version(">=2.0,<3.0") == (2, 0)
    assert _parse_version("abc") == ()


def test_version_in_range():
    assert _version_in_range("1.0.0", "<2.0.0")
    assert _version_in_range("1.5.0", "<2.0.0")
    assert not _version_in_range("2.0.0", "<2.0.0")
    assert _version_in_range("1.0.0", ">=0.5,<2.0")
    assert not _version_in_range("3.0.0", ">=0.5,<2.0")
    assert _version_in_range("1.5.0", ">=1.0,<2.0,>=0.5")


def test_scan_requirements_vulnerable():
    with tempfile.TemporaryDirectory() as tmp:
        req_path = str(Path(tmp, "requirements.txt"))
        req_path_enc = req_path.replace("\\", "/")
        with open(req_path, "w") as f:
            f.write("django==2.0.0\nflask==2.0.0\n")

        results = scan_manifest(req_path_enc)
        assert len(results) >= 1
        assert any(r["package"] == "django" for r in results)


def test_scan_package_json_vulnerable():
    with tempfile.TemporaryDirectory() as tmp:
        pkg_path = str(Path(tmp, "package.json"))
        pkg_path_enc = pkg_path.replace("\\", "/")
        with open(pkg_path, "w") as f:
            json.dump({"dependencies": {"express": "4.0.0", "lodash": "3.0.0"}}, f)

        results = scan_manifest(pkg_path_enc)
        assert len(results) >= 1
        assert any(r["package"] == "express" for r in results)
        assert any(r["package"] == "lodash" for r in results)


def test_scan_manifest_safe_version():
    with tempfile.TemporaryDirectory() as tmp:
        req_path = str(Path(tmp, "requirements.txt"))
        with open(req_path, "w") as f:
            f.write("django==5.1.4\n")

        results = scan_manifest(req_path)
        assert len(results) == 0


def test_scan_dependencies_integration():
    with tempfile.TemporaryDirectory() as tmp:
        req_path = Path(tmp, "requirements.txt")
        with open(req_path, "w") as f:
            f.write("django==2.0.0\nflask==2.0.0\n")

        findings = scan_dependencies(tmp)
        assert len(findings) >= 1
        for f in findings:
            assert f.category == "vulnerable_dependency"
            assert f.confidence == "high"
            assert f.severity.value in ("critical", "high", "medium", "low")


def test_scan_pom_xml_vulnerable():
    with tempfile.TemporaryDirectory() as tmp:
        pom_path = str(Path(tmp, "pom.xml"))
        with open(pom_path, "w") as f:
            f.write("""<?xml version="1.0"?>
<project>
  <dependencies>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>2.14.0</version>
    </dependency>
  </dependencies>
</project>""")

        results = scan_manifest(pom_path)
        assert len(results) >= 1
        assert any("log4j" in r["package"] for r in results)


def test_scan_composer_vulnerable():
    with tempfile.TemporaryDirectory() as tmp:
        composer_path = str(Path(tmp, "composer.json"))
        with open(composer_path, "w") as f:
            json.dump({"require": {"guzzlehttp/guzzle": "6.0.0"}}, f)

        results = scan_manifest(composer_path)
        assert len(results) >= 1
        assert any("guzzle" in r["package"] for r in results)
