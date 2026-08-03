from __future__ import annotations
import os
import re
from pathlib import Path
from typing import Optional

import yaml

from src.models import Finding, Severity, Rule
from src.rules.parser import ParsedFile, get_node_text

SOURCES_PATH = Path(__file__).resolve().parent.parent.parent / "config" / "sources.yaml"


def load_taint_config() -> dict:
    with open(str(SOURCES_PATH), "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


_SCOPE_TYPES = {
    "function_definition",
    "function_declaration",
    "arrow_function",
    "method_definition",
    "method_declaration",
    "constructor_declaration",
    "lambda",
}


def _is_scope_node(node_type: str) -> bool:
    return node_type in _SCOPE_TYPES


def _get_var_name(node, source: bytes) -> Optional[str]:
    if node.type == "identifier":
        return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")
    if node.type == "attribute":
        for child in node.children:
            name = _get_var_name(child, source)
            if name:
                return name
    if node.type in ("variable_name", "name"):
        return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")
    if node.type == "expression_list":
        for child in node.children:
            name = _get_var_name(child, source)
            if name:
                return name
    return None


def _extract_scope_variables(root_node, source: bytes, language: str) -> dict[str, list[str]]:
    nodes_by_scope: dict[Optional[int], list] = {}

    def _walk(node, scope_id: Optional[int] = None):
        if _is_scope_node(node.type):
            scope_id = node.id
            nodes_by_scope.setdefault(scope_id, [])

        for child in node.children:
            _walk(child, scope_id)

    _walk(root_node)
    return nodes_by_scope


def _collect_assignments(scope_node, source: bytes, language: str) -> list[tuple[str, str, int]]:
    assignments: list[tuple[str, str, int]] = []

    assign_types = {
        "assignment",
        "augmented_assignment",
        "variable_declarator",
        "assignment_expression",
        "local_variable_declaration",
        "short_var_declaration",
    }

    def _walk(node):
        if node.type in assign_types:
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")

            if left is None and node.type == "variable_declarator":
                for child in node.children:
                    if child.type in ("identifier", "variable_name", "name"):
                        left = child
                        break
                if left:
                    for child in node.children:
                        if child.type not in ("identifier", "variable_name", "name", "="):
                            right = child
                            break

            if left is None and node.type in ("local_variable_declaration",):
                decl = node.child_by_field_name("declarator")
                if decl:
                    return _walk(decl)

            if left is not None and right is not None:
                var_name = _get_var_name(left, source)
                rhs_text = get_node_text(right, source)
                if var_name and rhs_text:
                    line = node.start_point[0] + 1
                    assignments.append((var_name, rhs_text, line))

        for child in node.children:
            _walk(child)

    _walk(scope_node)
    return assignments


def _collect_call_args(call_node, source: bytes) -> list[str]:
    args_node = call_node.child_by_field_name("arguments")
    if args_node is None:
        for child in call_node.children:
            if child.type in ("arguments", "argument_list"):
                args_node = child
                break
    if args_node is None:
        return []

    args: list[str] = []
    for child in args_node.children:
        if child.type in (",", "(", ")", "{", "}",):
            continue
        args.append(get_node_text(child, source))
    return args


def _collect_calls(scope_node, source: bytes, language: str = "") -> list[tuple[str, list[str], int]]:
    calls: list[tuple[str, list[str], int]] = []

    call_types = {
        "call_expression",
        "call",
        "function_call",
        "method_invocation",
        "function_call_expression",
        "method_invocation_expression",
        "scoped_call_expression",
        "invocation_expression",
    }

    def _resolve_call_name(node):
        func_node = node.child_by_field_name("function")
        if func_node is not None:
            return get_node_text(func_node, source)

        name_node = node.child_by_field_name("name")
        obj_node = node.child_by_field_name("object")
        if name_node is not None:
            name_text = get_node_text(name_node, source)
            if obj_node is not None:
                obj_text = get_node_text(obj_node, source)
                return f"{obj_text}.{name_text}"
            return name_text

        if node.children:
            for child in node.children:
                if child.type not in ("arguments", "argument_list", "{", "}", ";", ",", ".", "::", "->"):
                    return get_node_text(child, source)
        return None

    def _walk(node):
        if node.type in call_types:
            func_name = _resolve_call_name(node)
            if func_name:
                func_name = func_name.split("\n")[0].strip()
                func_name = func_name.split("(")[0].strip()
                if func_name:
                    args = _collect_call_args(node, source)
                    line = node.start_point[0] + 1
                    calls.append((func_name, args, line))

        for child in node.children:
            _walk(child)

    _walk(scope_node)
    return calls


def _find_scopes(root_node) -> list:
    scopes: list = []

    def _walk(node):
        if _is_scope_node(node.type):
            scopes.append(node)
        for child in node.children:
            _walk(child)

    _walk(root_node)
    if not scopes:
        scopes.append(root_node)
    return scopes


def _get_func_name(scope_node, source: bytes) -> str:
    name_node = scope_node.child_by_field_name("name")
    if name_node:
        return source[name_node.start_byte:name_node.end_byte].decode("utf-8", errors="replace")
    if scope_node.type in ("arrow_function",):
        for child in scope_node.children:
            if child.type == "variable_declarator":
                left = child.child_by_field_name("left")
                if left:
                    return get_node_text(left, source)
    return ""


def _get_func_params(scope_node, source: bytes) -> list[str]:
    params_node = scope_node.child_by_field_name("parameters")
    if params_node is None:
        params_node = scope_node.child_by_field_name("formal_parameters")
    if params_node is None:
        return []
    params: list[str] = []
    for child in params_node.children:
        if child.type in (",", "(", ")", "{", "}", ":",):
            continue
        name = _get_var_name(child, source)
        if name:
            params.append(name)
    return params


def _build_var_regex(var_name: str) -> str:
    begin = r"(?<![a-zA-Z0-9_$])" if var_name.startswith("$") else r"\b"
    return begin + re.escape(var_name) + r"\b"


def run_taint_analysis(parsed: ParsedFile, rules: list[Rule]) -> list[Finding]:
    config = load_taint_config()
    lang_config = config.get(parsed.language, {})
    if not lang_config and parsed.language in ("typescript", "ts"):
        lang_config = config.get("javascript", {})
    source_patterns = lang_config.get("sources", [])

    sink_names: set[str] = set()
    for rule in rules:
        for name in rule.ast_function_names:
            sink_names.add(name)

    all_sink_names = sink_names | set(lang_config.get("sinks", []))

    if not source_patterns or not all_sink_names:
        return []

    findings: list[Finding] = []

    scopes = _find_scopes(parsed.root_node)

    param_dangerous: dict[str, set[int]] = {}
    for scope_node in scopes:
        func_name = _get_func_name(scope_node, parsed.source)
        if not func_name:
            func_name = ":" + str(scope_node.id)
        params = _get_func_params(scope_node, parsed.source)
        if not params:
            continue
        scope_assignments = _collect_assignments(scope_node, parsed.source, parsed.language)
        scope_calls = _collect_calls(scope_node, parsed.source, parsed.language)
        pseudo_origin: dict[str, int] = {p: i for i, p in enumerate(params)}
        changed2 = True
        while changed2:
            changed2 = False
            for var_name, rhs_text, _line in scope_assignments:
                if var_name in pseudo_origin:
                    continue
                for tv, origin in list(pseudo_origin.items()):
                    if re.search(_build_var_regex(tv), rhs_text):
                        pseudo_origin[var_name] = origin
                        changed2 = True
                        break
        dangerous_indices: set[int] = set()
        for call_name, args, line_no in scope_calls:
            short_name = call_name.rsplit(".", 1)[-1] if "." in call_name else call_name
            short_name = short_name.rsplit("->", 1)[-1] if "->" in short_name else short_name
            if call_name in all_sink_names or short_name in all_sink_names:
                for arg_text in args:
                    for tv, origin in pseudo_origin.items():
                        if re.search(_build_var_regex(tv), arg_text):
                            dangerous_indices.add(origin)
                            break
        if dangerous_indices:
            param_dangerous[func_name] = dangerous_indices

    for scope_node in scopes:
        assignments = _collect_assignments(scope_node, parsed.source, parsed.language)
        calls = _collect_calls(scope_node, parsed.source, parsed.language)

        tainted_vars: dict[str, bool] = {}

        for var_name, rhs_text, _line in assignments:
            for pattern in source_patterns:
                try:
                    if re.search(pattern, rhs_text, re.IGNORECASE):
                        tainted_vars[var_name] = True
                        break
                except re.error:
                    continue

        changed = True
        while changed:
            changed = False
            for var_name, rhs_text, _line in assignments:
                if var_name in tainted_vars:
                    continue
                for tvar in tainted_vars:
                    if re.search(_build_var_regex(tvar), rhs_text):
                        tainted_vars[var_name] = True
                        changed = True
                        break

        for func_name, args, line_no in calls:
            func_short = func_name.rsplit(".", 1)[-1] if "." in func_name else func_name
            func_short = func_short.rsplit("->", 1)[-1] if "->" in func_short else func_short

            in_sinks = func_name in all_sink_names or func_short in all_sink_names
            interproc_info = param_dangerous.get(func_name) or param_dangerous.get(func_short)
            if not in_sinks and interproc_info is None:
                continue

            tainted_args = []
            check_all = in_sinks
            check_indices = interproc_info if interproc_info is not None else set()
            for i, arg in enumerate(args):
                if not check_all and i not in check_indices:
                    continue
                for tvar in tainted_vars:
                    if re.search(_build_var_regex(tvar), arg):
                        tainted_args.append(arg)
                        break

            if tainted_args:
                rule_for_sink = None
                for rule in rules:
                    if func_name in rule.ast_function_names or func_short in rule.ast_function_names:
                        rule_for_sink = rule
                        break

                if rule_for_sink is None:
                    for rule in rules:
                        for rp in rule.regex_patterns:
                            try:
                                if re.search(r'\b' + re.escape(func_name) + r'\b', rp, re.IGNORECASE) or \
                                   re.search(r'\b' + re.escape(func_short) + r'\b', rp, re.IGNORECASE):
                                    rule_for_sink = rule
                                    break
                            except re.error:
                                pass
                        if rule_for_sink:
                            break

                category = "tainted_sink"
                description = f"Flujo de datos de usuario detectado hacia función peligrosa `{func_name}()`"
                remediation = "Valida y sanitiza los datos de usuario antes de pasarlos a funciones peligrosas."
                severity = Severity.HIGH
                cwe = "CWE-20"

                if rule_for_sink:
                    category = rule_for_sink.category
                    description = f"{rule_for_sink.description_template}: `{func_name}()` recibe datos de usuario no sanitizados"
                    remediation = rule_for_sink.remediation
                    severity = rule_for_sink.severity
                    cwe = rule_for_sink.cwe

                line_idx = line_no - 1
                context_start = max(0, line_idx - 1)
                context_end = min(len(parsed.lines), line_idx + 2)
                snippet = "\n".join(parsed.lines[context_start:context_end]).strip()

                confidence = "high"
                if "/test/" in parsed.path or "/tests/" in parsed.path or os.path.basename(parsed.path).startswith("test_"):
                    confidence = "medium"

                findings.append(Finding(
                    id=f"TAINT-{category[:4].upper()}",
                    category=category,
                    severity=severity,
                    cwe=cwe,
                    language=parsed.language,
                    file_path=parsed.path,
                    line_number=line_no,
                    code_snippet=snippet,
                    description=description,
                    remediation=remediation,
                    confidence=confidence,
                ))

    return findings
