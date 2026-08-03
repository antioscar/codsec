from __future__ import annotations
from pathlib import Path
from typing import Optional

from src.models import Finding, Severity
from src.llm.parsing import parse_json_response


SEMANTIC_SYSTEM = """Eres un auditor de seguridad de código experto. Analiza el siguiente código fuente y encuentra vulnerabilidades de seguridad que NO estén cubiertas por las categorías clásicas de SAST (SQL injection, XSS, command injection, path traversal, hardcoded secrets, SSRF, insecure deserialization, dynamic exec, insecure crypto, open redirect, CSRF, security headers, info disclosure).

Céntrate en problemas como:
- Lógica de autenticación/autorización débil
- Race conditions o TOCTOU
- IDOR (Insecure Direct Object Reference)
- Server-side request forgery sutil
- Problemas de manejo de sesiones
- XML External Entity (XXE)
- Configuraciones inseguras específicas
- Manejo inadecuado de errores con información sensible
- Inyección de templates (SSTI)
- Vulnerabilidades de negocio

Responde ÚNICAMENTE con un array JSON. Cada elemento debe tener:
- "category": categoría en snake_case
- "cwe": código CWE (ej. "CWE-284")
- "severity": "critical", "high", "medium" o "low"
- "line_number": número de línea aproximado (entero)
- "description": descripción del problema en español
- "remediation": pasos de remediación en español
- "confidence": "high", "medium" o "low"

Si no encontrás ninguna vulnerabilidad, responde con un array vacío: []"""


def semantic_scan(
    file_paths: list[str],
    client,
    max_files: int = 20,
    on_progress: Optional[callable] = None,
) -> list[Finding]:
    from src.discovery import language_from_extension

    targets: list[str] = []
    for fp in file_paths:
        lang = language_from_extension(fp)
        if lang is not None:
            targets.append(fp)

    if len(targets) > max_files:
        targets = targets[:max_files]

    findings: list[Finding] = []
    counter = 0

    for i, file_path in enumerate(targets):
        language = language_from_extension(file_path) or "unknown"
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                source = f.read()
        except Exception:
            continue

        if not source.strip():
            continue

        max_chars = 8000
        if len(source) > max_chars:
            source = source[:max_chars] + "\n// [código truncado ...]"

        messages = [
            {"role": "system", "content": SEMANTIC_SYSTEM},
            {"role": "user", "content": f"Lenguaje: {language}\n\nCódigo:\n```\n{source}\n```"},
        ]

        try:
            response = client.chat(messages)
            parsed = parse_json_response(response)
            if isinstance(parsed, list):
                for item in parsed:
                    if not isinstance(item, dict):
                        continue
                    counter += 1
                    severity_str = item.get("severity", "medium")
                    try:
                        severity = Severity(severity_str)
                    except ValueError:
                        severity = Severity.MEDIUM

                    confidence = item.get("confidence", "medium")
                    if confidence not in ("high", "medium", "low"):
                        confidence = "medium"

                    line_no = item.get("line_number", 1)
                    try:
                        line_no = int(line_no)
                    except (TypeError, ValueError):
                        line_no = 1

                    findings.append(Finding(
                        id=f"AI-SEM-{counter:04d}",
                        category=item.get("category", "ai_semantic"),
                        severity=severity,
                        cwe=item.get("cwe", "CWE-20"),
                        language=language,
                        file_path=file_path,
                        line_number=line_no,
                        code_snippet=f"[Análisis semántico IA] {item.get('description', '')}",
                        description=item.get("description", "Vulnerabilidad detectada por análisis semántico IA"),
                        remediation=item.get("remediation", "Revisa la lógica e implementa controles adecuados"),
                        confidence="medium",
                    ))
        except Exception:
            continue

        if on_progress:
            on_progress(i + 1, len(targets), f"Análisis IA {i + 1}/{len(targets)}")

    return findings
