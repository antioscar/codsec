from __future__ import annotations
import json
import re


def parse_json_response(text: str) -> dict | list | None:
    """Extract JSON from an LLM response, handling code fences and extra text."""
    if isinstance(text, bytes):
        text = text.decode("utf-8", errors="replace")
    text = text.strip()
    if not text:
        return None

    code_fence = re.search(r"```(?:json)?\s*([\s\S]*?)```", text)
    if code_fence:
        text = code_fence.group(1).strip()

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    for prefix in ("{", "["):
        idx = text.find(prefix)
        if idx == -1:
            continue
        depth = 0
        in_string = False
        escape = False
        for i in range(idx, len(text)):
            ch = text[i]
            if escape:
                escape = False
                continue
            if ch == "\\" and in_string:
                escape = True
                continue
            if ch == '"':
                in_string = not in_string
                continue
            if in_string:
                continue
            if ch in ("{", "["):
                depth += 1
            elif ch in ("}", "]"):
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[idx:i + 1])
                    except json.JSONDecodeError:
                        break
        break

    return None
