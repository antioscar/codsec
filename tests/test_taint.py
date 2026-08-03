from __future__ import annotations
import tempfile
from pathlib import Path

from src.rules.engine import load_rules, analyze_file
from src.rules.parser import parse_file
from src.rules.taint import run_taint_analysis


def test_taint_python_sqli_high_confidence():
    with tempfile.TemporaryDirectory() as tmp:
        file_path = str(Path(tmp, "app.py"))
        Path(file_path).write_text(
            'def login(request):\n'
            '    user = request.GET.get("user")\n'
            '    query = "SELECT * FROM users WHERE user=\'" + user + "\'"\n'
            '    cursor.execute(query)\n'
        )

        rules = load_rules()
        findings = analyze_file(file_path, "python", rules)

        sqli = [f for f in findings if f.category == "sql_injection"]
        assert len(sqli) >= 1
        high_conf = [f for f in sqli if f.confidence == "high"]
        assert len(high_conf) >= 1, f"Expected high confidence SQLi, got: {[(f.confidence, f.line_number) for f in sqli]}"


def test_taint_python_cmd_injection_high():
    with tempfile.TemporaryDirectory() as tmp:
        file_path = str(Path(tmp, "app.py"))
        Path(file_path).write_text(
            'import os\n'
            'def ping(request):\n'
            '    host = request.GET.get("host")\n'
            '    os.system("ping " + host)\n'
        )

        rules = load_rules()
        findings = analyze_file(file_path, "python", rules)

        cmds = [f for f in findings if f.category == "command_injection"]
        assert len(cmds) >= 1
        high_conf = [f for f in cmds if f.confidence == "high"]
        assert len(high_conf) >= 1, f"Expected high confidence cmd injection"


def test_taint_no_false_positive_on_constant():
    with tempfile.TemporaryDirectory() as tmp:
        file_path = str(Path(tmp, "app.py"))
        Path(file_path).write_text(
            'import os\n'
            'def ping():\n'
            '    host = "localhost"\n'
            '    os.system("ping " + host)\n'
        )

        rules = load_rules()
        findings = analyze_file(file_path, "python", rules)

        tainted = [f for f in findings if f.category == "tainted_sink"]
        assert len(tainted) == 0, f"Expected no tainted sinks for constants, got {len(tainted)}"

        cmds = [f for f in findings if f.category == "command_injection"]
        assert len(cmds) >= 1
        for f in cmds:
            assert f.confidence != "high", "Should not be high confidence without user input"


def test_taint_js_xss_high():
    with tempfile.TemporaryDirectory() as tmp:
        file_path = str(Path(tmp, "app.js"))
        Path(file_path).write_text(
            'function render(req) {\n'
            '    var name = req.query.name;\n'
            '    document.write(name);\n'
            '}\n'
        )

        rules = load_rules()
        findings = analyze_file(file_path, "javascript", rules)

        xss = [f for f in findings if f.category == "xss"]
        assert len(xss) >= 1
        high_conf = [f for f in xss if f.confidence == "high"]
        assert len(high_conf) >= 1, f"Expected high confidence XSS, got confidences: {[f.confidence for f in xss]}"


def test_taint_propagation():
    with tempfile.TemporaryDirectory() as tmp:
        file_path = str(Path(tmp, "app.py"))
        Path(file_path).write_text(
            'def handler(request):\n'
            '    uid = request.GET.get("id")\n'
            '    name = uid\n'
            '    result = "x" + name\n'
            '    cursor.execute(result)\n'
        )

        rules = load_rules()
        findings = analyze_file(file_path, "python", rules)

        sqli = [f for f in findings if f.category == "sql_injection"]
        high_conf = [f for f in sqli if f.confidence == "high"]
        assert len(high_conf) >= 1, f"Propagation should mark the sink as high confidence. Got: {[(f.confidence, f.line_number) for f in sqli]}"


def test_taint_python_eval_high():
    with tempfile.TemporaryDirectory() as tmp:
        file_path = str(Path(tmp, "app.py"))
        Path(file_path).write_text(
            'def execute(request):\n'
            '    code = request.POST.get("code")\n'
            '    eval(code)\n'
        )

        rules = load_rules()
        findings = analyze_file(file_path, "python", rules)

        dyn = [f for f in findings if f.category == "dynamic_exec"]
        high_conf = [f for f in dyn if f.confidence == "high"]
        assert len(high_conf) >= 1, f"Expected high confidence dynamic exec. Got: {[(f.confidence, f.line_number) for f in dyn]}"


def test_taint_python_secrets_unchanged():
    with tempfile.TemporaryDirectory() as tmp:
        file_path = str(Path(tmp, "config.py"))
        Path(file_path).write_text('API_KEY = "sk-1234567890abcdef1234567890abcdef"\n')

        rules = load_rules()
        findings = analyze_file(file_path, "python", rules)

        secrets = [f for f in findings if f.category == "hardcoded_secrets"]
        assert len(secrets) >= 1
        for f in secrets:
            assert f.confidence != "low", "Secrets should be medium confidence"


def test_taint_php_sqli_procedural():
    with tempfile.TemporaryDirectory() as tmp:
        file_path = str(Path(tmp, "app.php"))
        Path(file_path).write_text(
            '<?php\n'
            '$id = $_GET["id"];\n'
            '$q = "SELECT * FROM users WHERE id=\'" . $id . "\'";\n'
            'mysqli_query($conn, $q);\n'
            '?>\n'
        )

        rules = load_rules()
        findings = analyze_file(file_path, "php", rules)

        sqli = [f for f in findings if f.category == "sql_injection"]
        assert len(sqli) >= 1, f"Expected SQLi findings in PHP procedural, got {len(sqli)}"
        high_conf = [f for f in sqli if f.confidence == "high"]
        assert len(high_conf) >= 1, f"Expected high confidence via taint, got: {[(f.confidence, f.line_number) for f in sqli]}"


def test_taint_java_sqli_high():
    with tempfile.TemporaryDirectory() as tmp:
        file_path = str(Path(tmp, "Test.java"))
        Path(file_path).write_text(
            'public class Test {\n'
            '  void doGet(HttpServletRequest request) throws Exception {\n'
            '    String id = request.getParameter("id");\n'
            '    String q = "SELECT * FROM users WHERE id=\'" + id + "\'";\n'
            '    stmt.executeQuery(q);\n'
            '  }\n'
            '}\n'
        )

        rules = load_rules()
        findings = analyze_file(file_path, "java", rules)

        sqli = [f for f in findings if f.category == "sql_injection"]
        assert len(sqli) >= 1, f"Expected SQLi findings in Java, got {len(sqli)}"
        high_conf = [f for f in sqli if f.confidence == "high"]
        assert len(high_conf) >= 1, f"Expected high confidence via taint, got: {[(f.confidence, f.line_number) for f in sqli]}"


def test_taint_typescript_sqli_high():
    with tempfile.TemporaryDirectory() as tmp:
        file_path = str(Path(tmp, "app.ts"))
        Path(file_path).write_text(
            'function handler(req: any) {\n'
            '  const q = "SELECT * FROM users WHERE id=\'" + req.query.id + "\'";\n'
            '  db.query(q);\n'
            '}\n'
        )

        rules = load_rules()
        findings = analyze_file(file_path, "typescript", rules)

        sqli = [f for f in findings if f.category == "sql_injection"]
        assert len(sqli) >= 1, f"Expected SQLi findings in TS via taint, got {len(sqli)}"
        high_conf = [f for f in sqli if f.confidence == "high"]
        assert len(high_conf) >= 1, f"Expected high confidence taint in TS"


def test_taint_php_no_false_positive():
    with tempfile.TemporaryDirectory() as tmp:
        file_path = str(Path(tmp, "app.php"))
        Path(file_path).write_text(
            '<?php\n'
            '$host = "localhost";\n'
            '$q = "SELECT * FROM users";\n'
            'mysqli_query($conn, $q);\n'
            '?>\n'
        )

        rules = load_rules()
        findings = analyze_file(file_path, "php", rules)

        tainted = [f for f in findings if f.category == "tainted_sink"]
        assert len(tainted) == 0, f"Expected no tainted sinks for constants in PHP"


def test_interproc_python_wrapper_called_with_taint():
    with tempfile.TemporaryDirectory() as tmp:
        file_path = str(Path(tmp, "app.py"))
        Path(file_path).write_text(
            'import os\n'
            'from flask import request\n'
            'def execute_cmd(cmd):\n'
            '    os.system(cmd)\n'
            'def run():\n'
            '    user_input = request.args.get("cmd")\n'
            '    execute_cmd(user_input)\n'
        )

        rules = load_rules()
        findings = analyze_file(file_path, "python", rules)

        tainted = [f for f in findings if "execute_cmd" in f.description or "os.system" in f.description]
        assert len(tainted) >= 1, f"Expected interprocedural finding for execute_cmd wrapper"


def test_interproc_python_wrapper_no_fp():
    with tempfile.TemporaryDirectory() as tmp:
        file_path = str(Path(tmp, "app.py"))
        Path(file_path).write_text(
            'import os\n'
            'from flask import request\n'
            'def execute_cmd(cmd):\n'
            '    os.system("echo hello")\n'
            'def run():\n'
            '    user_input = request.args.get("cmd")\n'
            '    execute_cmd(user_input)\n'
        )

        rules = load_rules()
        findings = analyze_file(file_path, "python", rules)

        inter_proc = [f for f in findings if "execute_cmd" in f.description and f.category == "tainted_sink"]
        assert len(inter_proc) == 0, (
            f"execute_cmd with hardcoded arg should not produce interproc taint finding"
        )


def test_interproc_python_propagation():
    with tempfile.TemporaryDirectory() as tmp:
        file_path = str(Path(tmp, "app.py"))
        Path(file_path).write_text(
            'import os\n'
            'from flask import request\n'
            'def process_input(data):\n'
            '    val = data\n'
            '    os.system(val)\n'
            'def handler():\n'
            '    user_input = request.args.get("name")\n'
            '    process_input(user_input)\n'
        )

        rules = load_rules()
        findings = analyze_file(file_path, "python", rules)

        inter = [f for f in findings if "process_input" in f.description]
        assert len(inter) >= 1, f"Expected interprocedural finding with propagated param"
