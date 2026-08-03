from __future__ import annotations
import os
from pathlib import Path
from typing import Optional

LANGUAGE_EXTENSIONS: dict[str, list[str]] = {
    "python": [".py"],
    "javascript": [".js", ".mjs", ".cjs"],
    "typescript": [".ts", ".tsx", ".mts", ".cts"],
    "php": [".php", ".phtml", ".php3", ".php4", ".php5", ".phtml"],
    "java": [".java", ".jsp"],
    "go": [".go"],
    "csharp": [".cs"],
    "ruby": [".rb"],
    "kotlin": [".kt", ".kts"],
    "swift": [".swift"],
    "rust": [".rs"],
}

EXCLUDE_DIRS: set[str] = {
    "node_modules",
    ".git",
    "dist",
    "build",
    "vendor",
    "__pycache__",
    ".next",
    "venv",
    ".venv",
    ".idea",
    ".vscode",
    "target",
    "out",
    ".angular",
    "coverage",
    ".nyc_output",
    ".tox",
    ".eggs",
    ".mypy_cache",
    ".pytest_cache",
    ".terraform",
}

EXCLUDE_FILES: set[str] = {
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "composer.lock",
    "poetry.lock",
    "Pipfile.lock",
}


def language_from_extension(file_path: str) -> Optional[str]:
    ext = Path(file_path).suffix.lower()
    for lang, exts in LANGUAGE_EXTENSIONS.items():
        if ext in exts:
            return lang
    return None


def discover_files(
    target_path: str,
    languages: Optional[list[str]] = None,
    exclude_dirs: Optional[set[str]] = None,
) -> list[str]:
    if languages is None:
        languages = list(LANGUAGE_EXTENSIONS.keys())

    allowed_extensions: set[str] = set()
    for lang in languages:
        exts = LANGUAGE_EXTENSIONS.get(lang, [])
        allowed_extensions.update(exts)

    if exclude_dirs is None:
        exclude_dirs = EXCLUDE_DIRS

    exclude_dirs_full = exclude_dirs | EXCLUDE_DIRS

    discovered: list[str] = []

    for root, dirs, files in os.walk(target_path, topdown=True):
        dirs[:] = [d for d in dirs if d not in exclude_dirs_full]

        for file in files:
            if file in EXCLUDE_FILES:
                continue
            ext = Path(file).suffix.lower()
            if ext in allowed_extensions:
                discovered.append(os.path.join(root, file))

    return discovered


def detect_languages(files: list[str]) -> dict[str, int]:
    lang_counts: dict[str, int] = {}
    for f in files:
        lang = language_from_extension(f)
        if lang:
            lang_counts[lang] = lang_counts.get(lang, 0) + 1
    return lang_counts
