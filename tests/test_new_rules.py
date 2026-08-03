from __future__ import annotations
import tempfile
from pathlib import Path

from src.rules.engine import load_rules, analyze_file


def test_ssti_python_template_injection():
    with tempfile.TemporaryDirectory() as tmp:
        file_path = str(Path(tmp, "app.py"))
        Path(file_path).write_text(
            'from flask import Flask, request, render_template_string\n'
            'app = Flask(__name__)\n'
            '@app.route("/hello")\n'
            'def hello():\n'
            '    name = request.args.get("name")\n'
            '    return render_template_string(f"<h1>Hello {name}</h1>")\n'
        )
        rules = load_rules()
        findings = analyze_file(file_path, "python", rules)
        ssti = [f for f in findings if f.category == "ssti"]
        assert len(ssti) >= 1, f"Expected SSTI finding, got {[f.category for f in findings]}"


def test_xxe_python_xml_parsing():
    with tempfile.TemporaryDirectory() as tmp:
        file_path = str(Path(tmp, "app.py"))
        Path(file_path).write_text(
            'import xml.etree.ElementTree as ET\n'
            'from flask import Flask, request\n'
            'app = Flask(__name__)\n'
            '@app.route("/xml")\n'
            'def parse_xml():\n'
            '    xml_data = request.data\n'
            '    tree = ET.fromstring(xml_data)\n'
            '    return "parsed"\n'
        )
        rules = load_rules()
        findings = analyze_file(file_path, "python", rules)
        xxe = [f for f in findings if f.category == "xxe"]
        assert len(xxe) >= 1, f"Expected XXE finding, got {[f.category for f in findings]}"


def test_weak_hash_python_md5():
    with tempfile.TemporaryDirectory() as tmp:
        file_path = str(Path(tmp, "app.py"))
        Path(file_path).write_text(
            'import hashlib\n'
            'def hash_password(password):\n'
            '    return hashlib.md5(password.encode()).hexdigest()\n'
        )
        rules = load_rules()
        findings = analyze_file(file_path, "python", rules)
        wh = [f for f in findings if f.category == "weak_hash"]
        assert len(wh) >= 1, f"Expected weak_hash finding, got {[f.category for f in findings]}"


def test_log_injection_python():
    with tempfile.TemporaryDirectory() as tmp:
        file_path = str(Path(tmp, "app.py"))
        Path(file_path).write_text(
            'import logging\n'
            'from flask import Flask, request\n'
            'app = Flask(__name__)\n'
            'logger = logging.getLogger(__name__)\n'
            '@app.route("/login")\n'
            'def login():\n'
            '    user = request.args.get("user")\n'
            '    logger.info(f"Login attempt by {user}")\n'
            '    return "ok"\n'
        )
        rules = load_rules()
        findings = analyze_file(file_path, "python", rules)
        li_findings = [f for f in findings if f.category == "log_injection"]
        assert len(li_findings) >= 1, f"Expected log_injection finding, got {[f.category for f in findings]}"


def test_zip_slip_python():
    with tempfile.TemporaryDirectory() as tmp:
        file_path = str(Path(tmp, "app.py"))
        Path(file_path).write_text(
            'import zipfile\n'
            'def extract_archive(filename):\n'
            '    with zipfile.ZipFile(filename, "r") as zf:\n'
            '        zf.extractall("/tmp/")\n'
        )
        rules = load_rules()
        findings = analyze_file(file_path, "python", rules)
        zs = [f for f in findings if f.category == "zip_slip"]
        assert len(zs) >= 1, f"Expected zip_slip finding, got {[f.category for f in findings]}"


def test_prototype_pollution_javascript():
    with tempfile.TemporaryDirectory() as tmp:
        file_path = str(Path(tmp, "app.js"))
        Path(file_path).write_text(
            'const _ = require("lodash");\n'
            'const app = require("express")();\n'
            'app.post("/update", (req, res) => {\n'
            '    _.merge({}, req.body);\n'
            '    res.send("ok");\n'
            '});\n'
        )
        rules = load_rules()
        findings = analyze_file(file_path, "javascript", rules)
        pp = [f for f in findings if f.category == "prototype_pollution"]
        assert len(pp) >= 1, f"Expected prototype_pollution finding, got {[f.category for f in findings]}"


def test_ldap_injection_php():
    with tempfile.TemporaryDirectory() as tmp:
        file_path = str(Path(tmp, "app.php"))
        Path(file_path).write_text(
            '<?php\n'
            '$user = $_GET["user"];\n'
            'ldap_search($ds, "dc=example,dc=com", "uid=" . $user);\n'
            '?>\n'
        )
        rules = load_rules()
        findings = analyze_file(file_path, "php", rules)
        ldap_findings = [f for f in findings if f.category == "ldap_injection"]
        assert len(ldap_findings) >= 1, f"Expected ldap_injection finding, got {[f.category for f in findings]}"
