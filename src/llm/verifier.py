from __future__ import annotations
from typing import Optional

from src.models import Finding
from src.llm.parsing import parse_json_response


VERIFIER_SYSTEM = """Eres un auditor de seguridad de código. Tu tarea es revisar hallazgos de un SAST y decidir si son verdaderos positivos (confirmed) o falsos positivos (false_positive).

Responde ÚNICAMENTE con un objeto JSON:
{"verdict": "confirmed" o "false_positive", "reason": "breve explicación en español"}

Reglas:
- confirmed: el código realmente ejecuta la operación insegura descrita.
- false_positive: el código es inocuo (ej. string constante, comentario, entorno de prueba, placeholder)."""


def _build_verify_prompt(finding: Finding, extended_context: str) -> str:
    return f"""Hallazgo del analizador estático:
- Categoría: {finding.category.replace('_', ' ').title()}
- CWE: {finding.cwe}
- Descripción del analizador: {finding.description}
- Lenguaje: {finding.language}
- Línea: {finding.line_number}

Código (contexto extendido alrededor de la línea afectada):
```
{extended_context}
```

¿Es este hallazgo un verdadero positivo (confirmed) o un falso positivo (false_positive)?"""


def _read_context(file_path: str, line_number: int, context_lines: int = 8) -> str:
    if line_number <= 0:
        return "(archivo de manifiesto de dependencias — no hay código fuente)"
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        start = max(0, line_number - context_lines - 1)
        end = min(len(lines), line_number + context_lines)
        return "".join(lines[start:end]).strip()
    except Exception:
        return finding_snippet


finding_snippet = "(no se pudo leer el archivo)"


def verify_findings(
    findings: list[Finding],
    client,
    max_findings: int = 30,
    on_progress: Optional[callable] = None,
) -> dict:
    """Returns dict mapping finding.id -> verdict. Verdict is one of: confirmed, false_positive."""
    from src.llm.provider import LLMClient

    targets = [f for f in findings if f.line_number > 0]
    if len(targets) > max_findings:
        targets.sort(key=lambda f: f.severity.order)
        targets = targets[:max_findings]

    verdicts: dict[str, str] = {}

    for i, finding in enumerate(targets):
        context = _read_context(finding.file_path, finding.line_number)
        prompt = _build_verify_prompt(finding, context)

        messages = [
            {"role": "system", "content": VERIFIER_SYSTEM},
            {"role": "user", "content": prompt},
        ]

        try:
            response = client.chat(messages)
            parsed = parse_json_response(response)
            if isinstance(parsed, dict) and "verdict" in parsed:
                verdicts[finding.id] = parsed["verdict"]
            else:
                verdicts[finding.id] = "unknown"
        except Exception:
            verdicts[finding.id] = "error"

        if on_progress:
            on_progress(i + 1, len(targets), f"Verificación IA {i + 1}/{len(targets)}")
        elif len(targets) <= 10:
            pass

    return verdicts


def apply_verdicts(findings: list[Finding], verdicts: dict[str, str]) -> list[Finding]:
    result: list[Finding] = []
    for f in findings:
        verdict = verdicts.get(f.id, "unknown")
        if verdict == "false_positive":
            continue
        if verdict == "confirmed":
            f.confidence = "high"
        result.append(f)
    return result
