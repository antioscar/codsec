from __future__ import annotations
import json
import os
import re
from pathlib import Path

import yaml

from src.models import Finding, Severity

CVE_DB_PATH = Path(__file__).resolve().parent.parent / "config" / "dependencies" / "cve_db.yaml"

MANIFEST_PATTERNS = [
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "requirements.txt",
    "poetry.lock",
    "Pipfile.lock",
    "Pipfile",
    "composer.lock",
    "composer.json",
    "pom.xml",
    "go.mod",
    "Gemfile.lock",
    "packages.config",
    "Cargo.lock",
    "Package.swift",
]
CS_PROJ_PATTERN = re.compile(r"\.csproj$", re.IGNORECASE)


def _parse_version(version_str: str) -> tuple[int, ...]:
    clean = re.sub(r'[\^~>=<\s]', '', str(version_str))
    clean = clean.lstrip("v")
    first_part = clean.split(",")[0]
    parts = first_part.split(".")
    result = []
    for p in parts:
        try:
            result.append(int(p))
        except ValueError:
            break
    return tuple(result)


def _version_in_range(version: str, affected_range: str) -> bool:
    if not affected_range:
        return False

    ver = _parse_version(version)
    if not ver:
        return False

    conditions = [c.strip() for c in affected_range.split(",")]

    groups: list[list[str]] = []
    current_group: list[str] = []
    for cond in conditions:
        if not cond:
            continue
        if current_group and (cond.startswith(">=") or cond.startswith(">")):
            groups.append(current_group)
            current_group = [cond]
        else:
            current_group.append(cond)
    if current_group:
        groups.append(current_group)

    if not groups:
        groups = [conditions]

    for group in groups:
        match = True
        for cond in group:
            if cond.startswith("<="):
                target = _parse_version(cond[2:])
                if target and ver > target:
                    match = False
                    break
            elif cond.startswith(">="):
                target = _parse_version(cond[2:])
                if target and ver < target:
                    match = False
                    break
            elif cond.startswith("<"):
                target = _parse_version(cond[1:])
                if target and ver >= target:
                    match = False
                    break
            elif cond.startswith(">"):
                target = _parse_version(cond[1:])
                if target and ver <= target:
                    match = False
                    break
        if match:
            return True

    return False


def _clean_version(ver: str) -> str:
    ver = ver.strip()
    ver = re.sub(r'[\^~>=<\s]', '', ver)
    ver = ver.lstrip("v")
    ver = ver.split("\n")[0].strip()
    return ver if ver else "0.0.0"


def scan_manifest(file_path: str) -> list[dict]:
    with open(CVE_DB_PATH, "r", encoding="utf-8") as f:
        db = yaml.safe_load(f) or {}

    vulnerabilities = db.get("vulnerabilities", [])
    filename = os.path.basename(file_path).lower()
    results: list[dict] = []

    if filename == "requirements.txt":
        ecosystem = "pypi"
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("-"):
                    continue
                match = re.match(r'^([A-Za-z0-9_\-\.]+)\s*([><=!~]+.*)?', line)
                if not match:
                    continue
                pkg = match.group(1).lower()
                ver = _clean_version(match.group(2) if match.lastindex and match.lastindex >= 2 else "0.0.0")
                results.extend(_check_pkg(pkg, ver, ecosystem, vulnerabilities))

    elif filename == "package.json":
        ecosystem = "npm"
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                data = json.load(f)
            all_deps = {}
            all_deps.update(data.get("dependencies", {}))
            all_deps.update(data.get("devDependencies", {}))
            for pkg, ver in all_deps.items():
                results.extend(_check_pkg(pkg, _clean_version(ver), ecosystem, vulnerabilities))
        except (json.JSONDecodeError, OSError):
            pass

    elif filename == "package-lock.json":
        ecosystem = "npm"
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                data = json.load(f)
            all_deps = {}
            if "packages" in data:
                for key, pkg_info in data["packages"].items():
                    if key and isinstance(pkg_info, dict) and "version" in pkg_info:
                        name = key.rsplit("node_modules/", 1)[-1] if "node_modules/" in key else key
                        if name:
                            all_deps[name] = pkg_info["version"]
            elif "dependencies" in data:
                for name, info in data["dependencies"].items():
                    if isinstance(info, dict) and "version" in info:
                        all_deps[name] = info["version"]
                    elif isinstance(info, str):
                        all_deps[name] = info
            for pkg, ver in all_deps.items():
                results.extend(_check_pkg(pkg, _clean_version(ver), ecosystem, vulnerabilities))
        except (json.JSONDecodeError, OSError):
            pass

    elif filename == "yarn.lock":
        ecosystem = "npm"
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            entries = re.split(r'\n\n+', content)
            for entry in entries:
                name_match = re.match(r'^"?(@?[^@\n]+)@', entry.strip())
                ver_match = re.search(r'^\s+version\s+"([^"]+)"', entry, re.MULTILINE)
                if name_match and ver_match:
                    pkg = name_match.group(1).strip('"').strip()
                    ver = ver_match.group(1)
                    results.extend(_check_pkg(pkg, _clean_version(ver), ecosystem, vulnerabilities))
        except OSError:
            pass

    elif filename == "poetry.lock":
        ecosystem = "pypi"
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            for block in re.split(r'\n\[\[package\]\]\n', content):
                name = re.search(r'^name\s*=\s*"([^"]+)"', block, re.MULTILINE)
                version = re.search(r'^version\s*=\s*"([^"]+)"', block, re.MULTILINE)
                if name and version:
                    results.extend(_check_pkg(name.group(1), _clean_version(version.group(1)), ecosystem, vulnerabilities))
        except OSError:
            pass

    elif filename == "Pipfile.lock".lower():
        ecosystem = "pypi"
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                data = json.load(f)
            for section in ("default", "develop"):
                for pkg, pkg_info in data.get(section, {}).items():
                    ver = pkg_info.get("version", "0.0.0")
                    results.extend(_check_pkg(pkg, _clean_version(ver), ecosystem, vulnerabilities))
        except (json.JSONDecodeError, OSError):
            pass

    elif filename == "pipfile":
        ecosystem = "pypi"
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            in_packages = False
            for line in content.split("\n"):
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                if stripped in ("[packages]", "[dev-packages]"):
                    in_packages = True
                    continue
                if stripped.startswith("[") and stripped.endswith("]"):
                    in_packages = False
                    continue
                if in_packages:
                    m = re.match(r'^([A-Za-z0-9_\-\.]+)\s*=\s*(?:"==|==\s*"?)?([^"\']+)?', stripped)
                    if m:
                        ver = m.group(2).strip().strip('"').strip("'") if m.group(2) else "0.0.0"
                        if ver == "*":
                            ver = "0.0.0"
                        results.extend(_check_pkg(m.group(1).lower(), _clean_version(ver), ecosystem, vulnerabilities))
        except OSError:
            pass

    elif filename in ("composer.json", "composer.lock"):
        ecosystem = "composer"
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                data = json.load(f)

            if filename == "composer.json":
                all_deps = {}
                all_deps.update(data.get("require", {}))
                all_deps.update(data.get("require-dev", {}))
            else:
                all_deps = {}
                for pkg_data in data.get("packages", []):
                    all_deps[pkg_data.get("name", "")] = pkg_data.get("version", "*")

            for pkg, ver in all_deps.items():
                results.extend(_check_pkg(pkg, _clean_version(ver), ecosystem, vulnerabilities))
        except (json.JSONDecodeError, OSError):
            pass

    elif filename == "pom.xml":
        ecosystem = "maven"
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            dep_matches = re.finditer(
                r'<dependency>\s*<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>\s*(?:<version>([^<]+)</version>)?',
                content,
            )
            for m in dep_matches:
                group_id = m.group(1).strip()
                artifact_id = m.group(2).strip()
                version = m.group(3) or "0.0.0"
                pkg = f"{group_id}:{artifact_id}"
                results.extend(_check_pkg(pkg, _clean_version(version), ecosystem, vulnerabilities))

            props = dict(re.findall(r'<([^>]+\.version)>(.+?)</', content))
            for m in re.finditer(
                r'<dependency>\s*<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>\s*<version>\$\{([^}]+)\}</version>',
                content,
            ):
                group_id = m.group(1).strip()
                artifact_id = m.group(2).strip()
                prop_key = m.group(3).strip()
                version = props.get(prop_key, "0.0.0")
                pkg = f"{group_id}:{artifact_id}"
                results.extend(_check_pkg(pkg, _clean_version(version), ecosystem, vulnerabilities))
        except OSError:
            pass

    elif filename == "go.mod":
        ecosystem = "go"
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            in_require = False
            for line in content.split("\n"):
                stripped = line.strip()
                if not stripped or stripped.startswith("//"):
                    continue
                if stripped.startswith("require ("):
                    in_require = True
                    continue
                if stripped == ")" and in_require:
                    in_require = False
                    continue
                if stripped.startswith("require "):
                    m = re.match(r'require\s+(\S+)\s+(\S+)', stripped)
                    if m:
                        results.extend(_check_pkg(m.group(1), _clean_version(m.group(2)), ecosystem, vulnerabilities))
                elif in_require:
                    m = re.match(r'(\S+)\s+(\S+)', stripped)
                    if m:
                        results.extend(_check_pkg(m.group(1), _clean_version(m.group(2)), ecosystem, vulnerabilities))
                elif stripped.startswith("require\t"):
                    m = re.match(r'require\t(\S+)\t(\S+)', stripped) or re.match(r'require\s+(\S+)\s+(\S+)', stripped)
                    if m:
                        results.extend(_check_pkg(m.group(1), _clean_version(m.group(2)), ecosystem, vulnerabilities))
        except OSError:
            pass

    elif filename == "Gemfile.lock".lower():
        ecosystem = "ruby"
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            in_specs = False
            for line in content.split("\n"):
                stripped = line.strip()
                if re.match(r'^\s+specs:$', line):
                    in_specs = True
                    continue
                if in_specs and not line.startswith("    ") and stripped:
                    in_specs = False
                    continue
                if in_specs and line.startswith("    ") and stripped:
                    m = re.match(r'\s{4}(\S+)\s*\(([^)]+)\)', line)
                    if m:
                        results.extend(_check_pkg(m.group(1), _clean_version(m.group(2)), ecosystem, vulnerabilities))
        except OSError:
            pass

    elif filename == "packages.config":
        ecosystem = "nuget"
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            for m in re.finditer(r'<package\s+id="([^"]+)"[^>]*version="([^"]+)"', content):
                results.extend(_check_pkg(m.group(1), _clean_version(m.group(2)), ecosystem, vulnerabilities))
        except OSError:
            pass

    elif CS_PROJ_PATTERN.search(filename):
        ecosystem = "nuget"
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            for m in re.finditer(r'<PackageReference\s+Include="([^"]+)"[^>]*Version="([^"]+)"', content):
                results.extend(_check_pkg(m.group(1), _clean_version(m.group(2)), ecosystem, vulnerabilities))
        except OSError:
            pass

    elif filename == "cargo.lock":
        ecosystem = "cargo"
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            for block in re.split(r'\n\[\[package\]\]\n', content):
                nm = re.search(r'^name\s*=\s*"([^"]+)"', block, re.MULTILINE)
                vm = re.search(r'^version\s*=\s*"([^"]+)"', block, re.MULTILINE)
                if nm and vm:
                    results.extend(_check_pkg(nm.group(1), _clean_version(vm.group(1)), ecosystem, vulnerabilities))
        except OSError:
            pass

    elif filename == "package.swift":
        ecosystem = "swift"
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            for m in re.finditer(r'\.package\s*\(\s*url\s*:\s*"([^"]+)"', content):
                url = m.group(1)
                pkg_name = url.rstrip("/").split("/")[-1]
                if pkg_name.endswith(".git"):
                    pkg_name = pkg_name[:-4]
                remainder = content[m.end():m.end() + 300]
                ver_match = re.search(r'(?:from\s*:\s*)?\s*"([^"]+)"', remainder)
                ver = ver_match.group(1) if ver_match else "0.0.0"
                results.extend(_check_pkg(pkg_name, _clean_version(ver), ecosystem, vulnerabilities))
        except OSError:
            pass

    return results


def _check_pkg(pkg: str, version: str, ecosystem: str, vulnerabilities: list) -> list[dict]:
    results = []
    pkg_lower = pkg.lower().strip()

    for vuln in vulnerabilities:
        if vuln.get("ecosystem") != ecosystem:
            continue
        name = vuln.get("package", "").lower()
        if name != pkg_lower:
            continue
        if _version_in_range(version, vuln.get("affected", "")):
            results.append({
                "package": name,
                "version": version,
                "cve": vuln.get("cve", ""),
                "severity": vuln.get("severity", "medium"),
                "description": vuln.get("description", ""),
                "fixed": vuln.get("fixed", ""),
            })
    return results


def scan_dependencies(target_path: str) -> list[Finding]:
    findings: list[Finding] = []

    lower_patterns = [m.lower() for m in MANIFEST_PATTERNS]

    for root, dirs, files in os.walk(target_path):
        dirs[:] = [d for d in dirs if d not in {"node_modules", ".git", "vendor", "__pycache__", "venv", ".venv", "target"}]
        for file in files:
            fn_lower = file.lower()
            if fn_lower in lower_patterns or CS_PROJ_PATTERN.search(fn_lower):
                file_path = os.path.join(root, file)
                results = scan_manifest(file_path)
                for r in results:
                    sev_map = {
                        "critical": Severity.CRITICAL,
                        "high": Severity.HIGH,
                        "medium": Severity.MEDIUM,
                        "low": Severity.LOW,
                    }
                    severity = sev_map.get(r["severity"], Severity.MEDIUM)
                    findings.append(Finding(
                        id="",
                        category="vulnerable_dependency",
                        severity=severity,
                        cwe="CWE-1104",
                        language="",
                        file_path=file_path,
                        line_number=0,
                        code_snippet="",
                        description=f"Dependencia vulnerable: {r['package']}@{r['version']} — {r['cve']}: {r['description']}",
                        remediation=f"Actualizá {r['package']} a la versión {r.get('fixed', 'más reciente')}.",
                        confidence="high",
                    ))
    return findings


def collect_manifest_packages(target_path: str) -> list[tuple[str, str, str]]:
    packages: list[tuple[str, str, str]] = []
    lower_patterns = [m.lower() for m in MANIFEST_PATTERNS]
    for root, dirs, files in os.walk(target_path):
        dirs[:] = [d for d in dirs if d not in {"node_modules", ".git", "vendor", "__pycache__", "venv", ".venv", "target"}]
        for file in files:
            fn_lower = file.lower()
            if fn_lower not in lower_patterns and not CS_PROJ_PATTERN.search(fn_lower):
                continue
            file_path = os.path.join(root, file)
            raw = scan_manifest_raw(file_path)
            packages.extend(raw)
    return packages


def scan_manifest_raw(file_path: str) -> list[tuple[str, str, str]]:
    filename = os.path.basename(file_path).lower()
    raw: list[tuple[str, str, str]] = []

    try:
        if filename == "requirements.txt":
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or line.startswith("-"):
                        continue
                    m = re.match(r'^([A-Za-z0-9_\-\.]+)\s*([><=!~]+.*)?', line)
                    if m:
                        raw.append((m.group(1).lower(), _clean_version(m.group(2) if m.lastindex and m.lastindex >= 2 else "0.0.0"), "pypi"))
        elif filename in ("package.json", "package-lock.json"):
            eco = "npm"
            try:
                with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                    data = json.load(f)
                if filename == "package.json":
                    deps = {}
                    deps.update(data.get("dependencies", {}))
                    deps.update(data.get("devDependencies", {}))
                    for p, v in deps.items():
                        raw.append((p, _clean_version(v), eco))
                else:
                    if "packages" in data:
                        for key, info in data["packages"].items():
                            if key and isinstance(info, dict) and "version" in info:
                                name = key.rsplit("node_modules/", 1)[-1] if "node_modules/" in key else key
                                if name:
                                    raw.append((name, _clean_version(info["version"]), eco))
                    elif "dependencies" in data:
                        for name, info in data["dependencies"].items():
                            v = info.get("version", info) if isinstance(info, dict) else info
                            raw.append((name, _clean_version(v), eco))
            except Exception:
                pass
        elif filename == "yarn.lock":
            try:
                with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
                for entry in re.split(r'\n\n+', content):
                    nm = re.match(r'^"?(@?[^@\n]+)@', entry.strip())
                    vm = re.search(r'^\s+version\s+"([^"]+)"', entry, re.MULTILINE)
                    if nm and vm:
                        raw.append((nm.group(1).strip('"').strip(), _clean_version(vm.group(1)), "npm"))
            except Exception:
                pass
        elif filename == "poetry.lock":
            try:
                with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
                for block in re.split(r'\n\[\[package\]\]\n', content):
                    nm = re.search(r'^name\s*=\s*"([^"]+)"', block, re.MULTILINE)
                    vm = re.search(r'^version\s*=\s*"([^"]+)"', block, re.MULTILINE)
                    if nm and vm:
                        raw.append((nm.group(1), _clean_version(vm.group(1)), "pypi"))
            except Exception:
                pass
        elif filename == "Pipfile.lock".lower():
            try:
                with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                    data = json.load(f)
                for section in ("default", "develop"):
                    for pkg, info in data.get(section, {}).items():
                        raw.append((pkg, _clean_version(info.get("version", "0.0.0")), "pypi"))
            except Exception:
                pass
        elif filename == "pipfile":
            try:
                with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
                in_packages = False
                for line in content.split("\n"):
                    stripped = line.strip()
                    if not stripped or stripped.startswith("#"):
                        continue
                    if stripped in ("[packages]", "[dev-packages]"):
                        in_packages = True
                        continue
                    if stripped.startswith("[") and stripped.endswith("]"):
                        in_packages = False
                        continue
                    if in_packages:
                        m = re.match(r'^([A-Za-z0-9_\-\.]+)\s*=\s*(?:"==|==\s*"?)?([^"\']+)?', stripped)
                        if m:
                            ver = m.group(2).strip().strip('"').strip("'") if m.group(2) else "0.0.0"
                            if ver == "*":
                                ver = "0.0.0"
                            raw.append((m.group(1).lower(), _clean_version(ver), "pypi"))
            except Exception:
                pass
        elif filename in ("composer.json", "composer.lock"):
            try:
                with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                    data = json.load(f)
                deps = {}
                if filename == "composer.json":
                    deps.update(data.get("require", {}))
                    deps.update(data.get("require-dev", {}))
                else:
                    for pkg_data in data.get("packages", []):
                        deps[pkg_data.get("name", "")] = pkg_data.get("version", "0.0.0")
                for p, v in deps.items():
                    raw.append((p, _clean_version(v), "composer"))
            except Exception:
                pass
        elif filename == "pom.xml":
            try:
                with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
                for m in re.finditer(r'<dependency>\s*<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>\s*(?:<version>([^<]+)</version>)?', content):
                    raw.append((f"{m.group(1).strip()}:{m.group(2).strip()}", _clean_version(m.group(3) or "0.0.0"), "maven"))
                props = dict(re.findall(r'<([^>]+\.version)>(.+?)</', content))
                for m in re.finditer(r'<dependency>\s*<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>\s*<version>\$\{([^}]+)\}</version>', content):
                    raw.append((f"{m.group(1).strip()}:{m.group(2).strip()}", _clean_version(props.get(m.group(3).strip(), "0.0.0")), "maven"))
            except Exception:
                pass
        elif filename == "go.mod":
            try:
                with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
                in_require = False
                for line in content.split("\n"):
                    stripped = line.strip()
                    if not stripped or stripped.startswith("//"):
                        continue
                    if stripped.startswith("require ("):
                        in_require = True
                        continue
                    if stripped == ")" and in_require:
                        in_require = False
                        continue
                    if stripped.startswith("require ") or stripped.startswith("require\t"):
                        m = re.match(r'require\s+(\S+)\s+(\S+)', stripped)
                        if m:
                            raw.append((m.group(1), _clean_version(m.group(2)), "go"))
                    elif in_require:
                        m = re.match(r'(\S+)\s+(\S+)', stripped)
                        if m:
                            raw.append((m.group(1), _clean_version(m.group(2)), "go"))
            except Exception:
                pass
        elif filename == "Gemfile.lock".lower():
            try:
                with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
                in_specs = False
                for line in content.split("\n"):
                    if re.match(r'^\s+specs:$', line):
                        in_specs = True
                        continue
                    if in_specs and not line.startswith("    ") and line.strip():
                        in_specs = False
                        continue
                    if in_specs and line.startswith("    ") and line.strip():
                        m = re.match(r'\s{4}(\S+)\s*\(([^)]+)\)', line)
                        if m:
                            raw.append((m.group(1), _clean_version(m.group(2)), "ruby"))
            except Exception:
                pass
        elif filename == "packages.config":
            try:
                with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
                for m in re.finditer(r'<package\s+id="([^"]+)"[^>]*version="([^"]+)"', content):
                    raw.append((m.group(1), _clean_version(m.group(2)), "nuget"))
            except Exception:
                pass
        elif CS_PROJ_PATTERN.search(filename):
            try:
                with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
                for m in re.finditer(r'<PackageReference\s+Include="([^"]+)"[^>]*Version="([^"]+)"', content):
                    raw.append((m.group(1), _clean_version(m.group(2)), "nuget"))
            except Exception:
                pass
        elif filename == "cargo.lock":
            try:
                with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
                for block in re.split(r'\n\[\[package\]\]\n', content):
                    nm = re.search(r'^name\s*=\s*"([^"]+)"', block, re.MULTILINE)
                    vm = re.search(r'^version\s*=\s*"([^"]+)"', block, re.MULTILINE)
                    if nm and vm:
                        raw.append((nm.group(1), _clean_version(vm.group(1)), "cargo"))
            except Exception:
                pass
        elif filename == "package.swift":
            try:
                with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
                for m in re.finditer(r'\.package\s*\(\s*url\s*:\s*"([^"]+)"', content):
                    url = m.group(1)
                    pkg_name = url.rstrip("/").split("/")[-1]
                    if pkg_name.endswith(".git"):
                        pkg_name = pkg_name[:-4]
                    remainder = content[m.end():m.end() + 300]
                    ver_match = re.search(r'(?:from\s*:\s*)?\s*"([^"]+)"', remainder)
                    ver = ver_match.group(1) if ver_match else "0.0.0"
                    raw.append((pkg_name, _clean_version(ver), "swift"))
            except Exception:
                pass
    except Exception:
        pass

    return raw
