from __future__ import annotations
import json
from pathlib import Path

from unittest.mock import patch, MagicMock, mock_open

from src.deps_online import (
    _ecosystem_to_osv,
    _osv_severity,
    _is_version_affected,
    _load_cache,
    _save_cache,
    _query_osv_batch,
    scan_dependencies_online,
    CACHE_FILE,
)


class TestEcosystemMapping:
    def test_known_ecosystems(self):
        assert _ecosystem_to_osv("pypi") == "PyPI"
        assert _ecosystem_to_osv("npm") == "npm"
        assert _ecosystem_to_osv("maven") == "Maven"
        assert _ecosystem_to_osv("go") == "Go"
        assert _ecosystem_to_osv("ruby") == "RubyGems"
        assert _ecosystem_to_osv("nuget") == "NuGet"
        assert _ecosystem_to_osv("composer") == "Packagist"

    def test_unknown_ecosystem(self):
        assert _ecosystem_to_osv("unknown") is None
        assert _ecosystem_to_osv("") is None


class TestOsvSeverity:
    def test_cvss_v3_critical(self):
        vuln = {"severity": [{"type": "CVSS_V3", "score": "9.8"}]}
        assert _osv_severity(vuln) == "critical"

    def test_cvss_v3_high(self):
        vuln = {"severity": [{"type": "cvssv3", "score": "7.5"}]}
        assert _osv_severity(vuln) == "high"

    def test_cvss_v3_medium(self):
        vuln = {"severity": [{"type": "CVSS_V3.1", "score": "5.0"}]}
        assert _osv_severity(vuln) == "medium"

    def test_cvss_v3_low(self):
        vuln = {"severity": [{"type": "CVSS_V3", "score": "2.1"}]}
        assert _osv_severity(vuln) == "low"

    def test_cvss_v2_high(self):
        vuln = {"severity": [{"type": "CVSS_V2", "score": "7.0"}]}
        assert _osv_severity(vuln) == "high"

    def test_cvss_v2_medium(self):
        vuln = {"severity": [{"type": "cvssv2", "score": "5.0"}]}
        assert _osv_severity(vuln) == "medium"

    def test_cvss_v2_low(self):
        vuln = {"severity": [{"type": "CVSS_V2", "score": "3.0"}]}
        assert _osv_severity(vuln) == "low"

    def test_database_specific_severity(self):
        vuln = {"database_specific": {"severity": "HIGH"}}
        assert _osv_severity(vuln) == "high"

        vuln2 = {"database_specific": {"severity": "MODERATE"}}
        assert _osv_severity(vuln2) == "medium"

    def test_text_score_severity(self):
        vuln = {"severity": [{"type": "text", "score": "CRITICAL"}]}
        assert _osv_severity(vuln) == "critical"

    def test_no_severity_default(self):
        assert _osv_severity({}) == "medium"
        assert _osv_severity({"severity": []}) == "medium"


class TestIsVersionAffected:
    def test_exact_version_match(self):
        affected = [{"versions": ["1.0.0", "2.0.0"], "ranges": []}]
        result, fixed = _is_version_affected("1.0.0", affected)
        assert result is True
        assert fixed == ""

    def test_exact_version_no_match(self):
        affected = [{"versions": ["1.0.0"], "ranges": []}]
        result, fixed = _is_version_affected("2.0.0", affected)
        assert result is False

    def test_range_introduced_fixed_including(self):
        affected = [
            {
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [
                            {"introduced": "1.0.0"},
                            {"fixed": "1.5.0"},
                        ],
                    }
                ]
            }
        ]
        result, fixed = _is_version_affected("1.2.0", affected)
        assert result is True
        assert fixed == "1.5.0"

    def test_range_introduced_fixed_excluding(self):
        affected = [
            {
                "ranges": [
                    {
                        "type": "SEMVER",
                        "events": [
                            {"introduced": "1.0.0"},
                            {"fixed": "1.5.0"},
                        ],
                    }
                ]
            }
        ]
        result, fixed = _is_version_affected("2.0.0", affected)
        assert result is False

    def test_range_introduced_only(self):
        affected = [
            {
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "2.0.0"}],
                    }
                ]
            }
        ]
        result, fixed = _is_version_affected("2.5.0", affected)
        assert result is True
        assert fixed == ""

    def test_range_not_ecosystem_semver_skipped(self):
        affected = [
            {
                "ranges": [
                    {
                        "type": "GIT",
                        "events": [
                            {"introduced": "abc123"},
                            {"fixed": "def456"},
                        ],
                    }
                ]
            }
        ]
        result, fixed = _is_version_affected("1.0.0", affected)
        assert result is False

    def test_empty_affected(self):
        result, fixed = _is_version_affected("1.0.0", [])
        assert result is False

    def test_range_no_introduced(self):
        affected = [
            {
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"fixed": "1.5.0"}],
                    }
                ]
            }
        ]
        result, fixed = _is_version_affected("1.0.0", affected)
        assert result is False

    def test_is_version_affected_fixed_from_ranges(self):
        affected = [
            {
                "versions": ["1.0.0"],
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [
                            {"fixed": "2.0.0"},
                        ],
                    }
                ],
            }
        ]
        result, fixed = _is_version_affected("1.0.0", affected)
        assert result is True
        assert fixed == "2.0.0"


class TestScanDependenciesOnline:
    @patch("src.deps_online._query_osv_batch")
    @patch("src.deps_online._load_cache")
    @patch("src.deps_online._save_cache")
    def test_basic_scan_with_vulnerable_package(self, mock_save, mock_load, mock_query):
        mock_load.return_value = {}
        mock_query.return_value = {
            "PyPI:requests": [
                {
                    "id": "CVE-2023-1234",
                    "summary": "Vulnerability in requests",
                    "affected": [
                        {
                            "ranges": [
                                {
                                    "type": "ECOSYSTEM",
                                    "events": [{"introduced": "0"}],
                                }
                            ]
                        }
                    ],
                    "severity": [{"type": "CVSS_V3", "score": "9.0"}],
                }
            ]
        }

        results = scan_dependencies_online(
            "/tmp/test", [("requests", "2.28.0", "pypi")]
        )

        assert len(results) == 1
        assert results[0]["cve"] == "CVE-2023-1234"
        assert results[0]["severity"] == "critical"

    @patch("src.deps_online._query_osv_batch")
    @patch("src.deps_online._load_cache")
    @patch("src.deps_online._save_cache")
    def test_version_range_filtering_blocks_non_affected(self, mock_save, mock_load, mock_query):
        mock_load.return_value = {}
        mock_query.return_value = {
            "PyPI:flask": [
                {
                    "id": "CVE-2023-9999",
                    "summary": "Old Flask vuln",
                    "affected": [
                        {
                            "ranges": [
                                {
                                    "type": "ECOSYSTEM",
                                    "events": [
                                        {"introduced": "0"},
                                        {"fixed": "1.0.0"},
                                    ],
                                }
                            ]
                        }
                    ],
                    "severity": [{"type": "CVSS_V3", "score": "7.0"}],
                }
            ]
        }

        results = scan_dependencies_online(
            "/tmp/test", [("flask", "2.0.0", "pypi")]
        )

        assert len(results) == 0

    @patch("src.deps_online._query_osv_batch")
    @patch("src.deps_online._load_cache")
    @patch("src.deps_online._save_cache")
    def test_cve_alias_extraction(self, mock_save, mock_load, mock_query):
        mock_load.return_value = {}
        mock_query.return_value = {
            "npm:lodash": [
                {
                    "id": "GHSA-xxxx-xxxx-xxxx",
                    "aliases": ["CVE-2024-5678"],
                    "summary": "Prototype pollution in lodash",
                    "affected": [
                        {
                            "ranges": [
                                {
                                    "type": "ECOSYSTEM",
                                    "events": [{"introduced": "0"}],
                                }
                            ]
                        }
                    ],
                    "severity": [],
                }
            ]
        }

        results = scan_dependencies_online(
            "/tmp/test", [("lodash", "4.17.21", "npm")]
        )

        assert len(results) == 1
        assert results[0]["cve"] == "CVE-2024-5678"

    @patch("src.deps_online._query_osv_batch")
    @patch("src.deps_online._load_cache")
    @patch("src.deps_online._save_cache")
    def test_cache_hit(self, mock_save, mock_load, mock_query):
        import time
        cache_data = {
            "PyPI:requests:2.28.0": {
                "ts": time.time(),
                "vulns": [
                    {
                        "package": "requests",
                        "version": "2.28.0",
                        "cve": "CVE-2023-1234",
                        "severity": "high",
                        "description": "Cached vuln",
                        "fixed": "2.29.0",
                        "ecosystem": "PyPI",
                    }
                ],
            }
        }
        mock_load.return_value = cache_data

        results = scan_dependencies_online(
            "/tmp/test", [("requests", "2.28.0", "pypi")]
        )

        assert len(results) == 1
        assert results[0]["cve"] == "CVE-2023-1234"
        assert results[0]["severity"] == "high"
        mock_query.assert_not_called()

    @patch("src.deps_online._query_osv_batch")
    @patch("src.deps_online._load_cache")
    @patch("src.deps_online._save_cache")
    def test_expired_cache_refreshes(self, mock_save, mock_load, mock_query):
        old_ts = 0
        cache_data = {
            "PyPI:requests:2.28.0": {
                "ts": old_ts,
                "vulns": [
                    {
                        "package": "requests",
                        "version": "2.28.0",
                        "cve": "CVE-2022-9999",
                        "severity": "low",
                        "description": "Old",
                        "fixed": "",
                        "ecosystem": "PyPI",
                    }
                ],
            }
        }
        mock_load.return_value = cache_data
        mock_query.return_value = {
            "PyPI:requests": [
                {
                    "id": "CVE-2023-1234",
                    "summary": "New vuln",
                    "affected": [
                        {
                            "ranges": [
                                {
                                    "type": "ECOSYSTEM",
                                    "events": [{"introduced": "0"}],
                                }
                            ]
                        }
                    ],
                    "severity": [{"type": "CVSS_V3", "score": "9.0"}],
                }
            ]
        }

        results = scan_dependencies_online(
            "/tmp/test", [("requests", "2.28.0", "pypi")]
        )

        cves = [r["cve"] for r in results]
        assert "CVE-2023-1234" in cves
        mock_query.assert_called_once()

    @patch("src.deps_online._query_osv_batch")
    @patch("src.deps_online._load_cache")
    @patch("src.deps_online._save_cache")
    def test_unknown_ecosystem_skipped(self, mock_save, mock_load, mock_query):
        mock_load.return_value = {}

        results = scan_dependencies_online(
            "/tmp/test", [("pkg", "1.0.0", "unknown_eco")]
        )

        assert len(results) == 0
        mock_query.assert_not_called()

    @patch("src.deps_online._query_osv_batch")
    @patch("src.deps_online._load_cache")
    @patch("src.deps_online._save_cache")
    def test_no_packages_returns_empty(self, mock_save, mock_load, mock_query):
        results = scan_dependencies_online("/tmp/test", [])
        assert len(results) == 0

    @patch("src.deps_online._query_osv_batch")
    @patch("src.deps_online._load_cache")
    @patch("src.deps_online._save_cache")
    def test_multiple_packages_different_ecosystems(self, mock_save, mock_load, mock_query):
        mock_load.return_value = {}
        mock_query.return_value = {
            "PyPI:requests": [
                {
                    "id": "CVE-2023-PY",
                    "summary": "Python vuln",
                    "affected": [
                        {
                            "ranges": [
                                {
                                    "type": "ECOSYSTEM",
                                    "events": [{"introduced": "0"}],
                                }
                            ]
                        }
                    ],
                    "severity": [{"type": "CVSS_V3", "score": "8.0"}],
                }
            ],
            "npm:express": [
                {
                    "id": "CVE-2023-JS",
                    "summary": "JS vuln",
                    "affected": [
                        {
                            "ranges": [
                                {
                                    "type": "ECOSYSTEM",
                                    "events": [{"introduced": "0"}],
                                }
                            ]
                        }
                    ],
                    "severity": [{"type": "CVSS_V3", "score": "6.0"}],
                }
            ],
        }

        results = scan_dependencies_online(
            "/tmp/test",
            [("requests", "2.28.0", "pypi"), ("express", "4.18.0", "npm")],
        )

        cves = {r["cve"] for r in results}
        assert cves == {"CVE-2023-PY", "CVE-2023-JS"}


class TestCacheLoad:
    def test_cache_load_invalid_json(self):
        with patch.object(Path, "exists", return_value=True), \
             patch("builtins.open", mock_open(read_data="not valid json")):
            result = _load_cache()
            assert result == {}

    def test_cache_load_non_dict_data(self):
        with patch.object(Path, "exists", return_value=True), \
             patch("builtins.open", mock_open(read_data="[]")):
            result = _load_cache()
            assert result == {}

    def test_cache_load_file_not_found(self):
        with patch.object(Path, "exists", return_value=False):
            result = _load_cache()
            assert result == {}


class TestQueryOsvBatch:
    def test_query_osv_batch_httpx_not_installed(self):
        import builtins
        original_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == "httpx":
                raise ImportError("No module named httpx")
            return original_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=mock_import):
            result = _query_osv_batch(
                [{"package": {"name": "test", "ecosystem": "PyPI"}}]
            )
            assert result == {}

    def test_query_osv_batch_success(self):
        import sys
        mock_post_resp = MagicMock()
        mock_post_resp.json.return_value = {
            "vulns": [{"id": "CVE-123", "summary": "test"}]
        }
        mock_client = MagicMock()
        mock_client.post.return_value = mock_post_resp
        mock_httpx = MagicMock()
        mock_httpx.Client.return_value.__enter__.return_value = mock_client

        with patch.dict(sys.modules, {"httpx": mock_httpx}):
            result = _query_osv_batch(
                [{"package": {"name": "test", "ecosystem": "PyPI"}}]
            )
            assert "PyPI:test" in result
            assert len(result["PyPI:test"]) == 1
            assert result["PyPI:test"][0]["id"] == "CVE-123"

    def test_query_osv_batch_http_error(self):
        import sys
        mock_client = MagicMock()
        mock_client.post.side_effect = Exception("HTTP error")
        mock_httpx = MagicMock()
        mock_httpx.Client.return_value.__enter__.return_value = mock_client

        with patch.dict(sys.modules, {"httpx": mock_httpx}):
            result = _query_osv_batch(
                [{"package": {"name": "test", "ecosystem": "PyPI"}}]
            )
            assert result == {"PyPI:test": []}


class TestSaveCache:
    def test_save_cache(self):
        with patch.object(Path, "mkdir") as mock_mkdir, \
             patch("src.deps_online.json.dump") as mock_json_dump, \
             patch("builtins.open") as mock_open_fn:
            _save_cache({"key": "value"})
            mock_mkdir.assert_called_once()
            mock_open_fn.assert_called_once_with(
                str(CACHE_FILE), "w", encoding="utf-8"
            )
            mock_json_dump.assert_called_once()
