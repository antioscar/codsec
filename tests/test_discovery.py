from __future__ import annotations
import tempfile
import os
from pathlib import Path

from src.discovery import discover_files, language_from_extension, detect_languages


def test_language_from_extension():
    assert language_from_extension("app.py") == "python"
    assert language_from_extension("src/index.js") == "javascript"
    assert language_from_extension("components/App.tsx") == "typescript"
    assert language_from_extension("server.ts") == "typescript"
    assert language_from_extension("index.php") == "php"
    assert language_from_extension("UserService.java") == "java"
    assert language_from_extension("main.go") == "go"
    assert language_from_extension("Controller.cs") == "csharp"
    assert language_from_extension("app.rb") == "ruby"
    assert language_from_extension("README.md") is None
    assert language_from_extension("Makefile") is None


def test_discover_files_filter_languages():
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "app.py").write_text("")
        Path(tmp, "script.js").write_text("")
        Path(tmp, "config.json").write_text("")

        py_files = discover_files(tmp, languages=["python"])
        assert len(py_files) == 1
        assert py_files[0].endswith("app.py")

        js_files = discover_files(tmp, languages=["javascript", "typescript"])
        assert len(js_files) == 1
        assert js_files[0].endswith("script.js")


def test_discover_excludes_dirs():
    with tempfile.TemporaryDirectory() as tmp:
        os.makedirs(Path(tmp, "node_modules", "lib"))
        os.makedirs(Path(tmp, "src"))
        os.makedirs(Path(tmp, ".git"))
        Path(tmp, "node_modules", "lib", "index.js").write_text("")
        Path(tmp, "src", "app.py").write_text("")

        files = discover_files(tmp)
        assert len(files) == 1
        assert "src" in files[0]


def test_detect_languages():
    files = ["app.py", "server.js", "Page.tsx", "index.php"]
    counts = detect_languages(files)
    assert counts["python"] == 1
    assert counts["javascript"] == 1
    assert counts["typescript"] == 1
    assert counts["php"] == 1
