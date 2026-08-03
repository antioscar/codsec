from __future__ import annotations
from typing import Optional

from src.models import Finding
from src.llm.parsing import parse_json_response


REMEDIATION_SYSTEM = """Eres un experto en seguridad de aplicaciones. Tu tarea es generar pasos de remediación detallados y específicos para un hallazgo de seguridad.

Responde ÚNICAMENTE con un objeto JSON:
{"remediation": "pasos de remediación numerados:\n1. ...\n2. ...\n3. ..."}

Los pasos deben ser:
- Específicos al código mostrado (usa nombres de variables/funciones)
- Accionables (cambios concretos de código cuando sea posible)
- Seguir buenas prácticas de seguridad (OWASP, CERT)
- En español

No incluyas introducciones ni conclusiones. Solo el JSON.""" 


def enhance_remediation(
    finding: Finding,
    client,
) -> str:
    user_msg = f"""Hallazgo de seguridad:
- Categoría: {finding.category.replace('_', ' ').title()}
- CWE: {finding.cwe}
- Descripción: {finding.description}
- Lenguaje: {finding.language}
- Línea: {finding.line_number}
- Remediación actual: {finding.remediation}

Código:
```
{finding.code_snippet}
```

Genera pasos de remediación detallados y específicos para este hallazgo."""

    messages = [
        {"role": "system", "content": REMEDIATION_SYSTEM},
        {"role": "user", "content": user_msg},
    ]

    try:
        response = client.chat(messages)
        parsed = parse_json_response(response)
        if isinstance(parsed, dict) and "remediation" in parsed:
            return parsed["remediation"]
    except Exception:
        pass

    return finding.remediation


def enhance_all_remediations(
    findings: list[Finding],
    client,
    on_progress: Optional[callable] = None,
) -> None:
    """Mutates findings in-place with enhanced remediation."""
    targets = [f for f in findings if f.remediation and f.line_number > 0]
    for i, finding in enumerate(targets):
        new_rem = enhance_remediation(finding, client)
        finding.remediation = new_rem
        if on_progress:
            on_progress(i + 1, len(targets), f"Remediación IA {i + 1}/{len(targets)}")
