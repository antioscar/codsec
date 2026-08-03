from __future__ import annotations
from dataclasses import dataclass
from typing import Optional

import tree_sitter_python
import tree_sitter_javascript
import tree_sitter_php
import tree_sitter_java
import tree_sitter_go
import tree_sitter_c_sharp
import tree_sitter_ruby
import tree_sitter_typescript
import tree_sitter_kotlin
import tree_sitter_swift
import tree_sitter_rust
from tree_sitter import Language, Parser, Node, Point


@dataclass
class ParsedFile:
    path: str
    language: str
    source: bytes
    root_node: Node
    lines: list[str]


def _get_language(lang: str) -> Optional[Language]:
    if lang in ("python",):
        return Language(tree_sitter_python.language())
    if lang in ("javascript", "js"):
        return Language(tree_sitter_javascript.language())
    if lang in ("typescript", "ts"):
        return Language(tree_sitter_typescript.language_typescript())
    if lang in ("tsx",):
        return Language(tree_sitter_typescript.language_tsx())
    if lang == "php":
        return Language(tree_sitter_php.language_php())
    if lang == "java":
        return Language(tree_sitter_java.language())
    if lang == "go":
        return Language(tree_sitter_go.language())
    if lang == "csharp":
        return Language(tree_sitter_c_sharp.language())
    if lang == "ruby":
        return Language(tree_sitter_ruby.language())
    if lang == "kotlin":
        return Language(tree_sitter_kotlin.language())
    if lang == "swift":
        return Language(tree_sitter_swift.language())
    if lang == "rust":
        return Language(tree_sitter_rust.language())
    return None


def parse_file(file_path: str, language: str) -> Optional[ParsedFile]:
    lang_obj = _get_language(language)
    if lang_obj is None:
        return None

    parser = Parser(lang_obj)

    with open(file_path, "rb") as f:
        source = f.read()

    tree = parser.parse(source)
    lines = source.decode("utf-8", errors="replace").split("\n")

    return ParsedFile(
        path=file_path,
        language=language,
        source=source,
        root_node=tree.root_node,
        lines=lines,
    )


def find_function_calls(node: Node, source: bytes) -> list[tuple[str, int, int]]:
    results: list[tuple[str, int, int]] = []

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

    if node.type in call_types:
        try:
            func_node = node.child_by_field_name("function")
            if func_node is None:
                name_node = node.child_by_field_name("name")
                obj_node = node.child_by_field_name("object")
                if name_node is not None:
                    func_node = name_node
                    if obj_node is not None:
                        obj_text = source[obj_node.start_byte:obj_node.end_byte].decode("utf-8", errors="replace")
                        name_text = source[name_node.start_byte:name_node.end_byte].decode("utf-8", errors="replace")
                        name = f"{obj_text}.{name_text}"
                        name = name.split("\n")[0].strip()
                        if name:
                            results.append((name, node.start_point[0] + 1, node.start_point[1]))
                        return results
                else:
                    for child in node.children:
                        if child.type not in ("arguments", "argument_list", "{", "}", ";", ",", ".", "::", "->"):
                            func_node = child
                            break
            if func_node is not None:
                name = source[func_node.start_byte : func_node.end_byte].decode("utf-8", errors="replace")
                name = name.split("\n")[0].strip()
                if name:
                    results.append((name, node.start_point[0] + 1, node.start_point[1]))
        except Exception:
            pass

    for child in node.children:
        results.extend(find_function_calls(child, source))

    return results


def get_node_text(node: Node, source: bytes) -> str:
    return source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def mask_comments(parsed: ParsedFile) -> str:
    mask = bytearray(parsed.source)

    comment_types = {"comment", "block_comment", "line_comment"}

    def _walk(node: Node):
        if node.type in comment_types:
            for i in range(node.start_byte, node.end_byte):
                if mask[i:i+1] != b"\n" and mask[i:i+1] != b"\r":
                    mask[i:i+1] = b" "
        for child in node.children:
            _walk(child)

    _walk(parsed.root_node)
    return mask.decode("utf-8", errors="replace")
