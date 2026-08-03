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


def test_cors_misconfiguration_javascript():
    with tempfile.TemporaryDirectory() as tmp:
        file_path = str(Path(tmp, "app.js"))
        Path(file_path).write_text(
            'app.get("/api", (req, res) => {\n'
            '    res.header("Access-Control-Allow-Origin", "*");\n'
            '    res.send("ok");\n'
            '});\n'
        )
        rules = load_rules()
        findings = analyze_file(file_path, "javascript", rules)
        cors_findings = [f for f in findings if f.category == "cors_misconfiguration"]
        assert len(cors_findings) >= 1, f"Expected cors_misconfiguration finding, got {[f.category for f in findings]}"


def test_cors_misconfiguration_python():
    with tempfile.TemporaryDirectory() as tmp:
        file_path = str(Path(tmp, "app.py"))
        Path(file_path).write_text(
            'CORS_ALLOW_ALL_ORIGINS = True\n'
        )
        rules = load_rules()
        findings = analyze_file(file_path, "python", rules)
        cors_findings = [f for f in findings if f.category == "cors_misconfiguration"]
        assert len(cors_findings) >= 1, f"Expected cors finding, got {[f.category for f in findings]}"


def test_cookie_security_php():
    with tempfile.TemporaryDirectory() as tmp:
        file_path = str(Path(tmp, "app.php"))
        Path(file_path).write_text(
            '<?php\n'
            'setcookie("session", $value, time()+3600, "/");\n'
            '?>\n'
        )
        rules = load_rules()
        findings = analyze_file(file_path, "php", rules)
        cookie_findings = [f for f in findings if f.category == "cookie_security"]
        assert len(cookie_findings) >= 1, f"Expected cookie_security finding, got {[f.category for f in findings]}"


def test_cookie_security_django():
    with tempfile.TemporaryDirectory() as tmp:
        file_path = str(Path(tmp, "settings.py"))
        Path(file_path).write_text(
            'SESSION_COOKIE_SECURE = False\n'
            'SESSION_COOKIE_HTTPONLY = False\n'
        )
        rules = load_rules()
        findings = analyze_file(file_path, "python", rules)
        cookie_findings = [f for f in findings if f.category == "cookie_security"]
        assert len(cookie_findings) >= 1, f"Expected cookie finding, got {[f.category for f in findings]}"


def test_insecure_jwt_python():
    with tempfile.TemporaryDirectory() as tmp:
        file_path = str(Path(tmp, "app.py"))
        Path(file_path).write_text(
            'import jwt\n'
            'def verify(token):\n'
            '    return jwt.decode(token, "secret", algorithms=["HS256"])\n'
        )
        rules = load_rules()
        findings = analyze_file(file_path, "python", rules)
        jwt_findings = [f for f in findings if f.category == "insecure_jwt"]
        assert len(jwt_findings) >= 1, f"Expected insecure_jwt finding, got {[f.category for f in findings]}"


def test_insecure_jwt_weak_secret():
    with tempfile.TemporaryDirectory() as tmp:
        file_path = str(Path(tmp, "config.py"))
        Path(file_path).write_text(
            'JWT_SECRET = "secret"\n'
        )
        rules = load_rules()
        findings = analyze_file(file_path, "python", rules)
        jwt_findings = [f for f in findings if f.category == "insecure_jwt"]
        assert len(jwt_findings) >= 1, f"Expected insecure_jwt finding, got {[f.category for f in findings]}"


def test_nosql_injection_javascript():
    with tempfile.TemporaryDirectory() as tmp:
        file_path = str(Path(tmp, "app.js"))
        Path(file_path).write_text(
            'app.post("/user", (req, res) => {\n'
            '    const user = db.collection("users").find({ $where: req.body.query });\n'
            '    res.json(user);\n'
            '});\n'
        )
        rules = load_rules()
        findings = analyze_file(file_path, "javascript", rules)
        nosql = [f for f in findings if f.category == "nosql_injection"]
        assert len(nosql) >= 1, f"Expected nosql_injection finding, got {[f.category for f in findings]}"


def test_nosql_injection_python():
    with tempfile.TemporaryDirectory() as tmp:
        file_path = str(Path(tmp, "app.py"))
        Path(file_path).write_text(
            'from flask import Flask, request\n'
            'app = Flask(__name__)\n'
            '@app.route("/search")\n'
            'def search():\n'
            '    q = request.args.get("q")\n'
            '    return db.users.find({"name": {"$gt": q}})\n'
        )
        rules = load_rules()
        findings = analyze_file(file_path, "python", rules)
        nosql = [f for f in findings if f.category == "nosql_injection"]
        assert len(nosql) >= 1, f"Expected nosql_injection finding, got {[f.category for f in findings]}"


def test_insecure_random_javascript():
    with tempfile.TemporaryDirectory() as tmp:
        file_path = str(Path(tmp, "app.js"))
        Path(file_path).write_text(
            'function generateToken() {\n'
            '    return Math.random().toString(36);\n'
            '}\n'
        )
        rules = load_rules()
        findings = analyze_file(file_path, "javascript", rules)
        rand = [f for f in findings if f.category == "insecure_random"]
        assert len(rand) >= 1, f"Expected insecure_random finding, got {[f.category for f in findings]}"


def test_insecure_random_python():
    with tempfile.TemporaryDirectory() as tmp:
        file_path = str(Path(tmp, "app.py"))
        Path(file_path).write_text(
            'import random\n'
            'token = str(random.randint(1000, 9999))\n'
        )
        rules = load_rules()
        findings = analyze_file(file_path, "python", rules)
        rand = [f for f in findings if f.category == "insecure_random"]
        assert len(rand) >= 1, f"Expected insecure_random finding, got {[f.category for f in findings]}"


def test_idor_access_control_javascript():
    with tempfile.TemporaryDirectory() as tmp:
        file_path = str(Path(tmp, "app.js"))
        Path(file_path).write_text(
            'router.get("/user/info", (req, res) => {\n'
            '    db.findOne({ _id: req.params.id });\n'
            '    res.send("ok");\n'
            '});\n'
        )
        rules = load_rules()
        findings = analyze_file(file_path, "javascript", rules)
        idor = [f for f in findings if f.category == "idor_access_control"]
        assert len(idor) >= 1, f"Expected idor_access_control finding, got {[f.category for f in findings]}"


def test_unsafe_deserialization_advanced_python():
    with tempfile.TemporaryDirectory() as tmp:
        file_path = str(Path(tmp, "app.py"))
        Path(file_path).write_text(
            'import yaml\n'
            'def parse(data):\n'
            '    return yaml.unsafe_load(data)\n'
        )
        rules = load_rules()
        findings = analyze_file(file_path, "python", rules)
        deser = [f for f in findings if f.category == "unsafe_deserialization_advanced"]
        assert len(deser) >= 1, f"Expected unsafe_deserialization_advanced finding, got {[f.category for f in findings]}"


def test_http_parameter_pollution_javascript():
    with tempfile.TemporaryDirectory() as tmp:
        file_path = str(Path(tmp, "app.js"))
        Path(file_path).write_text(
            'app.get("/search", (req, res) => {\n'
            '    const page = parseInt(req.query.page);\n'
            '    res.send("ok");\n'
            '});\n'
        )
        rules = load_rules()
        findings = analyze_file(file_path, "javascript", rules)
        hpp = [f for f in findings if f.category == "http_parameter_pollution"]
        assert len(hpp) >= 1, f"Expected http_parameter_pollution finding, got {[f.category for f in findings]}"


def test_graphql_injection_javascript():
    with tempfile.TemporaryDirectory() as tmp:
        file_path = str(Path(tmp, "app.js"))
        Path(file_path).write_text(
            'const { ApolloServer } = require("apollo-server");\n'
            'const server = new ApolloServer({\n'
            '    typeDefs,\n'
            '    resolvers,\n'
            '    introspection: true,\n'
            '});\n'
        )
        rules = load_rules()
        findings = analyze_file(file_path, "javascript", rules)
        gql = [f for f in findings if f.category == "graphql_injection"]
        assert len(gql) >= 1, f"Expected graphql_injection finding, got {[f.category for f in findings]}"


def test_missing_auth_python():
    with tempfile.TemporaryDirectory() as tmp:
        file_path = str(Path(tmp, "app.py"))
        Path(file_path).write_text(
            'from flask import Flask\n'
            'app = Flask(__name__)\n'
            'app.get("/admin/delete/<id>")\n'
            'def admin_delete(id):\n'
            '    return f"Deleted {id}"\n'
        )
        rules = load_rules()
        findings = analyze_file(file_path, "python", rules)
        auth = [f for f in findings if f.category == "missing_auth"]
        assert len(auth) >= 1, f"Expected missing_auth finding, got {[f.category for f in findings]}"


def test_host_header_injection_python():
    with tempfile.TemporaryDirectory() as tmp:
        file_path = str(Path(tmp, "settings.py"))
        Path(file_path).write_text(
            'ALLOWED_HOSTS = ["*"]\n'
        )
        rules = load_rules()
        findings = analyze_file(file_path, "python", rules)
        hhi = [f for f in findings if f.category == "host_header_injection"]
        assert len(hhi) >= 1, f"Expected host_header_injection finding, got {[f.category for f in findings]}"


def test_insecure_file_upload_python():
    with tempfile.TemporaryDirectory() as tmp:
        file_path = str(Path(tmp, "app.py"))
        Path(file_path).write_text(
            'from flask import request\n'
            '@app.route("/upload", methods=["POST"])\n'
            'def upload():\n'
            '    request.files["file"].save("uploads/" + request.files["file"].filename)\n'
            '    return "ok"\n'
        )
        rules = load_rules()
        findings = analyze_file(file_path, "python", rules)
        upload = [f for f in findings if f.category == "insecure_file_upload"]
        assert len(upload) >= 1, f"Expected insecure_file_upload finding, got {[f.category for f in findings]}"


def test_spring_security_misconfig_java():
    with tempfile.TemporaryDirectory() as tmp:
        file_path = str(Path(tmp, "SecurityConfig.java"))
        Path(file_path).write_text(
            '@Configuration\n'
            '@EnableWebSecurity\n'
            'public class SecurityConfig {\n'
            '  protected void configure(HttpSecurity http) {\n'
            '    http.csrf().disable().authorizeHttpRequests().anyRequest().permitAll();\n'
            '  }\n'
            '}\n'
        )
        rules = load_rules()
        findings = analyze_file(file_path, "java", rules)
        spring = [f for f in findings if f.category == "spring_security_misconfig"]
        assert len(spring) >= 1, f"Expected spring_security_misconfig finding, got {[f.category for f in findings]}"


def test_django_security_misconfig():
    with tempfile.TemporaryDirectory() as tmp:
        file_path = str(Path(tmp, "settings.py"))
        Path(file_path).write_text(
            'DEBUG = True\n'
            'ALLOWED_HOSTS = ["*"]\n'
            'SECURE_SSL_REDIRECT = False\n'
        )
        rules = load_rules()
        findings = analyze_file(file_path, "python", rules)
        django = [f for f in findings if f.category == "django_security_misconfig"]
        assert len(django) >= 1, f"Expected django_security_misconfig finding, got {[f.category for f in findings]}"


def test_express_security_misconfig():
    with tempfile.TemporaryDirectory() as tmp:
        file_path = str(Path(tmp, "app.js"))
        Path(file_path).write_text(
            'const express = require("express");\n'
            'const app = express();\n'
            'app.get("/data", (req, res) => {\n'
            '    res.send(req.query.data);\n'
            '});\n'
        )
        rules = load_rules()
        findings = analyze_file(file_path, "javascript", rules)
        express_findings = [f for f in findings if f.category == "express_security_misconfig"]
        assert len(express_findings) >= 1, f"Expected express_security_misconfig finding, got {[f.category for f in findings]}"


def test_laravel_security_misconfig():
    with tempfile.TemporaryDirectory() as tmp:
        file_path = str(Path(tmp, "app.php"))
        Path(file_path).write_text(
            '<?php\n'
            'class Kernel {\n'
            '  public function boot() {\n'
            '    $this->withoutMiddleware();\n'
            '  }\n'
            '}\n'
        )
        rules = load_rules()
        findings = analyze_file(file_path, "php", rules)
        laravel = [f for f in findings if f.category == "laravel_security_misconfig"]
        assert len(laravel) >= 1, f"Expected laravel_security_misconfig finding, got {[f.category for f in findings]}"
