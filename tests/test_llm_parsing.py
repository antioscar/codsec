from __future__ import annotations


def test_parse_json_clean():
    from src.llm.parsing import parse_json_response

    result = parse_json_response('{"verdict": "confirmed", "reason": "real issue"}')
    assert result == {"verdict": "confirmed", "reason": "real issue"}


def test_parse_json_code_fence():
    from src.llm.parsing import parse_json_response

    result = parse_json_response('```json\n{"verdict": "false_positive"}\n```')
    assert result == {"verdict": "false_positive"}


def test_parse_json_with_text_around():
    from src.llm.parsing import parse_json_response

    result = parse_json_response('Sure, here you go:\n{"x": 1}\nHope that helps')
    assert result == {"x": 1}


def test_parse_json_array():
    from src.llm.parsing import parse_json_response

    result = parse_json_response('[{"a": 1}, {"b": 2}]')
    assert result == [{"a": 1}, {"b": 2}]


def test_parse_json_array_fence():
    from src.llm.parsing import parse_json_response

    result = parse_json_response('```json\n[{"cat": "test"}]\n```')
    assert result == [{"cat": "test"}]


def test_parse_json_empty():
    from src.llm.parsing import parse_json_response

    result = parse_json_response("")
    assert result is None


def test_parse_json_invalid():
    from src.llm.parsing import parse_json_response

    result = parse_json_response("not json at all")
    assert result is None


def test_parse_json_nested():
    from src.llm.parsing import parse_json_response

    result = parse_json_response('{"outer": {"inner": [1, 2, 3]}}')
    assert result == {"outer": {"inner": [1, 2, 3]}}
