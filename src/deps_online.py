from __future__ import annotations
import json
import os
import time
from pathlib import Path
from typing import Optional

from src.models import Finding, Severity

CACHE_DIR = Path(__file__).resolve().parent.parent / "cache"
CACHE_FILE = CACHE_DIR / "osv_cache.json"
CACHE_TTL_SECONDS = 86400


def _load_cache() -> dict:
    try:
        if CACHE_FILE.exists():
            with open(str(CACHE_FILE), "r", encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, OSError):
        pass
    return {}


def _save_cache(cache: dict):
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    with open(str(CACHE_FILE), "w", encoding="utf-8") as f:
        json.dump(cache, f, indent=2)


def _query_osv_batch(queries: list[dict]) -> dict[str, list[dict]]:
    try:
        import httpx
    except ImportError:
        return {}

    results: dict[str, list[dict]] = {}
    with httpx.Client(timeout=15.0) as client:
        for q in queries:
            try:
                resp = client.post(
                    "https://api.osv.dev/v1/query",
                    json=q,
                )
                resp.raise_for_status()
                data = resp.json()
                vulns = data.get("vulns", [])
                pkg_key = f"{q.get('package',{}).get('ecosystem','')}:{q.get('package',{}).get('name','')}"
                if vulns:
                    results[pkg_key] = vulns
                else:
                    results[pkg_key] = []
            except Exception:
                results[f"{q.get('package',{}).get('ecosystem','')}:{q.get('package',{}).get('name','')}"] = []
    return results


def _ecosystem_to_osv(ecosystem: str) -> Optional[str]:
    mapping = {
        "pypi": "PyPI",
        "npm": "npm",
        "maven": "Maven",
        "go": "Go",
        "ruby": "RubyGems",
        "nuget": "NuGet",
        "composer": "Packagist",
    }
    return mapping.get(ecosystem)


def _osv_severity(vuln: dict) -> str:
    for entry in vuln.get("severity", []):
        score_type = entry.get("type", "").lower()
        score_val = entry.get("score", "")
        if score_type in ("cvss_v3", "cvssv3", "cvss_v3.1"):
            score = float(score_val) if score_val else 0
            if score >= 9.0:
                return "critical"
            if score >= 7.0:
                return "high"
            if score >= 4.0:
                return "medium"
            return "low"
    for entry in vuln.get("severity", []):
        score_type = entry.get("type", "").lower()
        score_val = entry.get("score", "")
        if score_type in ("cvss_v2", "cvssv2"):
            score = float(score_val) if score_val else 0
            if score >= 7.0:
                return "high"
            if score >= 4.0:
                return "medium"
            return "low"
    db_sev = vuln.get("database_specific", {}).get("severity", "")
    if isinstance(db_sev, str):
        sev_lower = db_sev.lower()
        text_map = {"critical": "critical", "high": "high", "moderate": "medium", "medium": "medium", "low": "low"}
        if sev_lower in text_map:
            return text_map[sev_lower]
    for entry in vuln.get("severity", []):
        sev_text = str(entry.get("score", "")).lower()
        text_map = {"critical": "critical", "high": "high", "moderate": "medium", "medium": "medium", "low": "low"}
        if sev_text in text_map:
            return text_map[sev_text]
    return "medium"


def _is_version_affected(version: str, affected_list: list[dict]) -> tuple[bool, str]:
    from src.deps import _parse_version, _version_in_range

    fixed_ver = ""
    for aff in affected_list:
        for v in aff.get("versions", []):
            if v == version:
                for r in aff.get("ranges", []):
                    for evt in r.get("events", []):
                        if evt.get("fixed"):
                            fixed_ver = evt["fixed"]
                            break
                return True, fixed_ver

        for r in aff.get("ranges", []):
            rtype = r.get("type", "")
            if rtype not in ("ECOSYSTEM", "SEMVER", ""):
                continue
            events = r.get("events", [])
            introduced = None
            for evt in events:
                if evt.get("introduced") is not None:
                    introduced = evt["introduced"]
                if evt.get("fixed"):
                    fixed_ver = evt["fixed"]
            if introduced is None:
                continue
            condition = f">={introduced}"
            if fixed_ver:
                condition += f",<{fixed_ver}"
            if _version_in_range(version, condition):
                return True, fixed_ver
    return False, ""


def scan_dependencies_online(
    target_path: str,
    packages: list[tuple[str, str, str]],
) -> list[dict]:
    cache = _load_cache()
    now = time.time()

    queries: list[dict] = []
    for pkg, version, ecosystem in packages:
        osv_eco = _ecosystem_to_osv(ecosystem)
        if not osv_eco:
            continue
        queries.append({
            "package": {"name": pkg, "ecosystem": osv_eco},
            "version": version,
        })

    if not queries:
        return []

    results: list[dict] = []
    uncached_queries: list[dict] = []
    uncached_indices: list[int] = []

    for i, q in enumerate(queries):
        cache_key = f"{q['package']['ecosystem']}:{q['package']['name']}:{q['version']}"
        cached = cache.get(cache_key)
        if cached and isinstance(cached, dict) and now - cached.get("ts", 0) < CACHE_TTL_SECONDS:
            for vuln_data in cached.get("vulns", []):
                results.append(vuln_data)
        else:
            uncached_queries.append(q)
            uncached_indices.append(i)

    if uncached_queries:
        osv_results = _query_osv_batch(uncached_queries)
        for j, q in enumerate(uncached_queries):
            cache_key = f"{q['package']['ecosystem']}:{q['package']['name']}:{q['version']}"
            pkg_vulns = osv_results.get(
                f"{q['package']['ecosystem']}:{q['package']['name']}", []
            )
            cache[cache_key] = {"ts": now, "vulns": []}
            for vuln in pkg_vulns:
                affected = vuln.get("affected", [])
                is_vuln, fixed_ver = _is_version_affected(q["version"], affected)
                cve_id = vuln.get("id", "")
                if not cve_id.startswith("CVE-"):
                    for alias in vuln.get("aliases", []):
                        if alias.startswith("CVE-"):
                            cve_id = alias
                            break
                vuln_data = {
                    "package": q["package"]["name"],
                    "version": q["version"],
                    "cve": cve_id or vuln.get("id", ""),
                    "severity": _osv_severity(vuln),
                    "description": vuln.get("summary", vuln.get("details", ""))[:200],
                    "fixed": fixed_ver if is_vuln else "",
                    "ecosystem": q["package"]["ecosystem"],
                }
                if is_vuln:
                    cache[cache_key]["vulns"].append(vuln_data)
                    results.append(vuln_data)

        _save_cache(cache)

    return results
