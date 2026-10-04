"""Round 5: the JSON pre-check is linear (ReDoS)."""

import time

import pytest
from werkzeug.exceptions import BadRequest, RequestEntityTooLarge

from app.request_limits import MAX_JSON_DEPTH, MAX_JSON_VALUES, check_json_limits


def _elapsed(document):
    started = time.perf_counter()
    try:
        check_json_limits(document)
    except (BadRequest, RequestEntityTooLarge):
        pass
    return time.perf_counter() - started


@pytest.mark.parametrize("document", [
    '"' + '\\"' * 32_000,                       # the probe: an unterminated string of escaped quotes (64 KB)
    '["' + '\\"' * 512_000,                     # the same at 1 MB
    '"' + "\\\\" * 1_000_000,                   # 2 MB of escaped backslashes, unterminated
    '["' + '\\"' * 200_000 + '", ' * 50_000,    # escaped quotes then many unterminated strings
])
def test_redos_json_precheck_is_linear(document):
    assert _elapsed(document) < 0.5


def test_redos_json_precheck_is_fast_on_a_legal_32_mib_body():
    document = '{"file": "' + "A" * (32 * 1024 * 1024 - 20) + '"}'
    assert _elapsed(document) < 1.0


def test_redos_json_precheck_keeps_its_limits():
    check_json_limits('{"a": "[[[[{{{{ \\" ]]]", "b": [1, 2, {"c": "}"}]}')
    with pytest.raises(BadRequest):
        check_json_limits("[" * (MAX_JSON_DEPTH + 1))
    check_json_limits("[" * MAX_JSON_DEPTH + "]" * MAX_JSON_DEPTH)
    with pytest.raises(RequestEntityTooLarge):
        check_json_limits("[" + "0," * (MAX_JSON_VALUES + 1) + "0]")
    with pytest.raises(RequestEntityTooLarge):
        check_json_limits("]" * (MAX_JSON_VALUES + 1))
    check_json_limits('"' + "[" * 100 + '"')  # brackets inside a string never count
