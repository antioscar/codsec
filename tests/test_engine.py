from __future__ import annotations
import tempfile
from pathlib import Path

from src.rules.engine import load_rules, analyze_file, run_scan


def test_load_rules():
    rules = load_rules()
    assert len(rules) >= 9
    categories = {r.category for r in rules}
    assert "sql_injection" in categories
    assert "xss" in categories
    assert "hardcoded_secrets" in categories
    assert "command_injection" in categories


def test_analyze_python_sqli():
    with tempfile.TemporaryDirectory() as tmp:
        file_path = str(Path(tmp, "test.py"))
        Path(file_path).write_text('cursor.execute("SELECT * FROM users WHERE id=" + user_id)')

        rules = load_rules()
        findings = analyze_file(file_path, "python", rules)
        assert len(findings) >= 1
        assert any("SQL" in f.category or "sql" in f.category for f in findings)


def test_analyze_python_secrets():
    with tempfile.TemporaryDirectory() as tmp:
        file_path = str(Path(tmp, "config.py"))
        Path(file_path).write_text('API_KEY = "sk-1234567890abcdef1234567890abcdef"')

        rules = load_rules()
        findings = analyze_file(file_path, "python", rules)
        assert len(findings) >= 1
        assert any("secret" in f.category for f in findings)


def test_analyze_js_xss():
    with tempfile.TemporaryDirectory() as tmp:
        file_path = str(Path(tmp, "app.js"))
        Path(file_path).write_text('document.getElementById("x").innerHTML = userInput;')

        rules = load_rules()
        findings = analyze_file(file_path, "javascript", rules)
        assert len(findings) >= 1
        assert any("xss" in f.category for f in findings)


def test_analyze_python_cmd_injection():
    with tempfile.TemporaryDirectory() as tmp:
        file_path = str(Path(tmp, "app.py"))
        Path(file_path).write_text('os.system("ping " + host)')

        rules = load_rules()
        findings = analyze_file(file_path, "python", rules)
        assert len(findings) >= 1
        assert any("command" in f.category for f in findings)


def test_run_scan_multiple_files():
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "app.py").write_text('API_KEY = "sk-abc12345678901234567890123456"\neval("1+1")')
        Path(tmp, "util.js").write_text('document.body.innerHTML = data;')
        Path(tmp, "ignored.json").write_text('{}')

        findings = run_scan([
            str(Path(tmp, "app.py")),
            str(Path(tmp, "util.js")),
            str(Path(tmp, "ignored.json")),
        ])
        assert len(findings) >= 2


def test_analyze_php_sqli():
    with tempfile.TemporaryDirectory() as tmp:
        file_path = str(Path(tmp, "test.php"))
        Path(file_path).write_text('<?php $q = "SELECT * FROM users WHERE id = \'" . $id . "\'"; ?>')

        rules = load_rules()
        findings = analyze_file(file_path, "php", rules)
        assert len(findings) >= 1
        assert any("sql" in f.category for f in findings)


def test_analyze_php_xss():
    with tempfile.TemporaryDirectory() as tmp:
        file_path = str(Path(tmp, "view.php"))
        Path(file_path).write_text('<?php echo "<div>" . $_GET["user"] . "</div>"; ?>')

        rules = load_rules()
        findings = analyze_file(file_path, "php", rules)
        assert len(findings) >= 1
        assert any("xss" in f.category for f in findings)


def test_analyze_java_sqli():
    with tempfile.TemporaryDirectory() as tmp:
        file_path = str(Path(tmp, "Test.java"))
        Path(file_path).write_text('String q = "SELECT * FROM t WHERE id = \'" + id + "\'";')

        rules = load_rules()
        findings = analyze_file(file_path, "java", rules)
        assert len(findings) >= 1
        assert any("sql" in f.category for f in findings)


def test_analyze_java_secrets():
    with tempfile.TemporaryDirectory() as tmp:
        file_path = str(Path(tmp, "Config.java"))
        Path(file_path).write_text(
            'private static final String KEY = "sk-1234567890abcdef1234567890abcdef";'
        )

        rules = load_rules()
        findings = analyze_file(file_path, "java", rules)
        assert len(findings) >= 1
        assert any("secret" in f.category for f in findings)


def test_false_positive_comment():
    with tempfile.TemporaryDirectory() as tmp:
        file_path = str(Path(tmp, "test.py"))
        Path(file_path).write_text(
            '# eval("this is just a comment")\n'
            '# document.body.innerHTML = "example";\n'
            'x = 1 + 1\n'
        )

        rules = load_rules()
        findings = analyze_file(file_path, "python", rules)
        assert len(findings) == 0, f"Expected 0 findings for comments, got {len(findings)}"


def test_false_positive_secret_placeholder():
    with tempfile.TemporaryDirectory() as tmp:
        file_path = str(Path(tmp, "config.py"))
        Path(file_path).write_text(
            'API_KEY = "your-api-key-here"\n'
            'SECRET = "example-secret-change-me"\n'
        )

        rules = load_rules()
        findings = analyze_file(file_path, "python", rules)
        secret_findings = [f for f in findings if f.category == "hardcoded_secrets"]
        assert len(secret_findings) == 0, f"Expected 0 secret findings for placeholders, got {len(secret_findings)}"


def test_analyze_open_redirect():
    with tempfile.TemporaryDirectory() as tmp:
        file_path = str(Path(tmp, "app.py"))
        Path(file_path).write_text(
            'from django.http import HttpResponseRedirect\n'
            'def go(request):\n'
            '    return HttpResponseRedirect(request.GET.get("next"))\n'
        )

        rules = load_rules()
        findings = analyze_file(file_path, "python", rules)
        assert len(findings) >= 1
        assert any("open_redirect" in f.category for f in findings)


def test_analyze_csrf_endpoint():
    with tempfile.TemporaryDirectory() as tmp:
        file_path = str(Path(tmp, "app.py"))
        Path(file_path).write_text(
            '@app.route("/transfer", methods=["POST"])\n'
            'def transfer(): pass\n'
        )

        rules = load_rules()
        findings = analyze_file(file_path, "python", rules)
        assert len(findings) >= 1
        assert any("csrf" in f.category for f in findings)


def test_analyze_debug_mode():
    with tempfile.TemporaryDirectory() as tmp:
        file_path = str(Path(tmp, "config.py"))
        Path(file_path).write_text('DEBUG = True')

        rules = load_rules()
        findings = analyze_file(file_path, "python", rules)
        assert len(findings) >= 1
        assert any(f.category in ("security_headers", "info_disclosure") for f in findings)


def test_analyze_console_log_secret():
    with tempfile.TemporaryDirectory() as tmp:
        file_path = str(Path(tmp, "app.js"))
        Path(file_path).write_text('console.log("User token:", token);')

        rules = load_rules()
        findings = analyze_file(file_path, "javascript", rules)
        assert len(findings) >= 1
        assert any("info_disclosure" in f.category for f in findings)


def test_load_all_rules_count():
    rules = load_rules()
    categories = {r.category for r in rules}
    expected = {"sql_injection", "xss", "hardcoded_secrets", "command_injection",
                "path_traversal", "ssrf", "insecure_crypto", "insecure_deserialization",
                "dynamic_exec", "open_redirect", "csrf", "security_headers", "info_disclosure",
                "ssti", "xxe", "ldap_injection", "prototype_pollution", "log_injection",
                "zip_slip", "weak_hash", "cors_misconfiguration", "cookie_security", "insecure_jwt"}
    assert categories == expected


def test_analyze_go_sqli():
    with tempfile.TemporaryDirectory() as tmp:
        file_path = str(Path(tmp, "test.go"))
        Path(file_path).write_text(
            "package main\nfunc main() {\n    q := \"SELECT * FROM x WHERE name = '\" + userInput + \"'\"\n    db.Exec(q)\n}\n"
        )
        rules = load_rules()
        findings = analyze_file(file_path, "go", rules)
        assert len(findings) >= 1
        assert any(f.category == "sql_injection" for f in findings)


def test_analyze_csharp_sqli():
    with tempfile.TemporaryDirectory() as tmp:
        file_path = str(Path(tmp, "test.cs"))
        Path(file_path).write_text(
            'class X { void M() { string q = "SELECT * FROM x WHERE name = \'" + "input" + "\'"; SqlCommand cmd = new SqlCommand(q, null); cmd.ExecuteNonQuery(); } }'
        )
        rules = load_rules()
        findings = analyze_file(file_path, "csharp", rules)
        assert len(findings) >= 1
        assert any(f.category == "sql_injection" for f in findings)


def test_analyze_ruby_sqli():
    with tempfile.TemporaryDirectory() as tmp:
        file_path = str(Path(tmp, "test.rb"))
        Path(file_path).write_text(
            "def search()\n  q = params[:q]\n  ActiveRecord::Base.connection.execute('SELECT * FROM x WHERE name = ' + q)\nend\n"
        )
        rules = load_rules()
        findings = analyze_file(file_path, "ruby", rules)
        assert len(findings) >= 1
        assert any(f.category == "sql_injection" for f in findings)


def test_analyze_go_secrets():
    with tempfile.TemporaryDirectory() as tmp:
        file_path = str(Path(tmp, "test.go"))
        Path(file_path).write_text(
            'package main\nfunc main() {\n    password := "superSecret123"\n    apiKey := "sk-abcdef123456"\n}\n'
        )
        rules = load_rules()
        findings = analyze_file(file_path, "go", rules)
        assert len(findings) >= 1
        assert any(f.category == "hardcoded_secrets" for f in findings)


def test_analyze_csharp_secrets():
    with tempfile.TemporaryDirectory() as tmp:
        file_path = str(Path(tmp, "test.cs"))
        Path(file_path).write_text(
            'class X { void M() { var apiKey = "sk-abcdef123456"; } }'
        )
        rules = load_rules()
        findings = analyze_file(file_path, "csharp", rules)
        assert len(findings) >= 1
        assert any(f.category == "hardcoded_secrets" for f in findings)


def test_analyze_ruby_secrets():
    with tempfile.TemporaryDirectory() as tmp:
        file_path = str(Path(tmp, "test.rb"))
        Path(file_path).write_text(
            'api_key = "sk-abcdef123456"\nsecret_token = "my-secret-12345"'
        )
        rules = load_rules()
        findings = analyze_file(file_path, "ruby", rules)
        assert len(findings) >= 1
        assert any(f.category == "hardcoded_secrets" for f in findings)


def test_typescript_parse_and_analyze():
    with tempfile.TemporaryDirectory() as tmp:
        file_path = str(Path(tmp, "app.ts"))
        Path(file_path).write_text(
            'const API_KEY = "sk-1234567890abcdef1234567890abcdef";\n'
            'function handler(req: any) { const q = "SELECT * FROM t WHERE id=\'" + req.query.id + "\'"; db.query(q); }\n'
        )

        rules = load_rules()
        findings = analyze_file(file_path, "typescript", rules)
        assert len(findings) >= 1
        assert any(f.category == "hardcoded_secrets" for f in findings)


def test_tsx_parses():
    with tempfile.TemporaryDirectory() as tmp:
        file_path = str(Path(tmp, "App.tsx"))
        Path(file_path).write_text(
            'const App = () => <div className="app">Hello</div>;\n'
        )

        rules = load_rules()
        findings = analyze_file(file_path, "tsx", rules)
        assert len(findings) >= 0


def test_load_rules_skips_empty_yaml():
    import yaml
    with tempfile.TemporaryDirectory() as rules_dir:
        yaml_path = Path(rules_dir, "empty.yaml")
        yaml_path.write_text("   \n# just a comment\n")
        rules = load_rules(rules_dir=rules_dir)
        assert isinstance(rules, list)


def test_load_rules_validates_missing_id():
    import yaml
    with tempfile.TemporaryDirectory() as rules_dir:
        rule_data = {
            "category": "xss",
            "severity": "high",
            "languages": ["python"],
            "patterns": ["xss_pattern"],
        }
        yaml_path = Path(rules_dir, "missing_id.yaml")
        with open(yaml_path, "w") as f:
            yaml.dump(rule_data, f)

        import io
        import sys
        captured = io.StringIO()
        old_stderr = sys.stderr
        sys.stderr = captured
        try:
            rules = load_rules(rules_dir=rules_dir, validate=True)
        finally:
            sys.stderr = old_stderr

        output = captured.getvalue()
        assert "falta el campo 'id'" in output


def test_load_rules_validates_duplicate_id():
    import yaml
    with tempfile.TemporaryDirectory() as rules_dir:
        rule_data = {
            "id": "DUP-001",
            "category": "xss",
            "severity": "high",
            "languages": ["python"],
            "patterns": ["xss_pattern"],
        }
        Path(rules_dir, "rule_a.yaml").write_text(yaml.dump(rule_data))
        rule_data2 = dict(rule_data)
        rule_data2["category"] = "sql_injection"
        Path(rules_dir, "rule_b.yaml").write_text(yaml.dump(rule_data2))

        import io
        import sys
        captured = io.StringIO()
        old_stderr = sys.stderr
        sys.stderr = captured
        try:
            rules = load_rules(rules_dir=rules_dir, validate=True)
        finally:
            sys.stderr = old_stderr

        output = captured.getvalue()
        assert "duplicado" in output


def test_load_rules_validates_unknown_language():
    import yaml
    with tempfile.TemporaryDirectory() as rules_dir:
        rule_data = {
            "id": "BAD-LANG",
            "category": "xss",
            "severity": "high",
            "languages": ["foobar"],
            "patterns": ["xss_pattern"],
        }
        Path(rules_dir, "unknown_lang.yaml").write_text(yaml.dump(rule_data))

        import io
        import sys
        captured = io.StringIO()
        old_stderr = sys.stderr
        sys.stderr = captured
        try:
            rules = load_rules(rules_dir=rules_dir, validate=True)
        finally:
            sys.stderr = old_stderr

        output = captured.getvalue()
        assert "lenguajes desconocidos" in output


def test_analyze_file_parse_fallback():
    from unittest.mock import patch
    with tempfile.TemporaryDirectory() as tmp:
        file_path = str(Path(tmp, "app.txt"))
        Path(file_path).write_text('API_KEY = "sk-1234567890abcdef1234567890abcdef"')

        rules = load_rules()
        with patch("src.rules.engine.parse_file", return_value=None):
            findings = analyze_file(file_path, "python", rules)
        assert len(findings) >= 1
        assert any("secret" in f.category for f in findings)


def test_analyze_kotlin_sqli():
    with tempfile.TemporaryDirectory() as tmp:
        file_path = str(Path(tmp, "test.kt"))
        Path(file_path).write_text(
            'fun search(query: String) {\n'
            '    val q = "SELECT * FROM items WHERE name = \'" + query + "\'"\n'
            '    stmt.executeQuery(q)\n'
            '}\n'
        )
        rules = load_rules()
        findings = analyze_file(file_path, "kotlin", rules)
        assert len(findings) >= 1
        assert any(f.category == "sql_injection" for f in findings)


def test_analyze_kotlin_secrets():
    with tempfile.TemporaryDirectory() as tmp:
        file_path = str(Path(tmp, "config.kt"))
        Path(file_path).write_text(
            'val apiKey = "sk-1234567890abcdef1234567890abcdef"\n'
        )
        rules = load_rules()
        findings = analyze_file(file_path, "kotlin", rules)
        assert len(findings) >= 1
        assert any(f.category == "hardcoded_secrets" for f in findings)


def test_analyze_swift_sqli():
    with tempfile.TemporaryDirectory() as tmp:
        file_path = str(Path(tmp, "app.swift"))
        Path(file_path).write_text(
            'func search(query: String) {\n'
            '    let sql = "SELECT * FROM items WHERE name = \'" + query + "\'"\n'
            '    db.execute(sql)\n'
            '}\n'
        )
        rules = load_rules()
        findings = analyze_file(file_path, "swift", rules)
        assert len(findings) >= 1
        assert any(f.category == "sql_injection" for f in findings)


def test_analyze_swift_secrets():
    with tempfile.TemporaryDirectory() as tmp:
        file_path = str(Path(tmp, "config.swift"))
        Path(file_path).write_text(
            'let apiKey = "sk-abcdef1234567890abcdef123456"\n'
        )
        rules = load_rules()
        findings = analyze_file(file_path, "swift", rules)
        assert len(findings) >= 1
        assert any(f.category == "hardcoded_secrets" for f in findings)


def test_analyze_rust_sqli():
    with tempfile.TemporaryDirectory() as tmp:
        file_path = str(Path(tmp, "main.rs"))
        Path(file_path).write_text(
            'fn search(query: &str) {\n'
            '    let sql = "SELECT * FROM items WHERE name = \'" + query;\n'
            '    conn.execute(sql, []);\n'
            '}\n'
        )
        rules = load_rules()
        findings = analyze_file(file_path, "rust", rules)
        assert len(findings) >= 1
        assert any(f.category == "sql_injection" for f in findings)


def test_analyze_rust_secrets():
    with tempfile.TemporaryDirectory() as tmp:
        file_path = str(Path(tmp, "config.rs"))
        Path(file_path).write_text(
            'let api_key = "sk-1234567890abcdef1234567890abcdef";\n'
        )
        rules = load_rules()
        findings = analyze_file(file_path, "rust", rules)
        assert len(findings) >= 1
        assert any(f.category == "hardcoded_secrets" for f in findings)
