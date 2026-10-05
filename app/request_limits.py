"""Request body limits: every body is bounded before any code reads it.

Body size
---------
- A route accepts a body of at most ``REQUEST_BODY_LIMIT`` bytes (1 MiB)
  unless :data:`ROUTE_BODY_LIMITS` raises the limit for that route, and no
  route accepts more than ``MAX_CONTENT_LENGTH`` (32 MiB).
- A raised limit applies only to a request that authenticates (an API-key
  header or a signed-in session of an active, unexpired member). An anonymous
  request is held to the default on every route. The app refuses to start
  when :data:`ROUTE_BODY_LIMITS` names an endpoint it does not have.
- The limit is in force before any other request hook runs: the request
  class defaults to it and :func:`apply_route_body_limit` is the first
  ``before_request`` hook, so the CSRF check and every other path that runs
  before authentication read at most the default.
- A body over the limit answers 413, whether its length is declared
  (``Content-Length``, refused before any byte is read) or not (chunked,
  refused once the limit is passed); it is never truncated.

Forms
-----
An ``application/x-www-form-urlencoded`` body is at most
``MAX_FORM_MEMORY_SIZE`` bytes (500,000) with at most ``MAX_FORM_PARTS``
fields (1,000). In a ``multipart/form-data`` body each non-file field is at
most ``MAX_FORM_MEMORY_SIZE`` bytes, there are at most ``MAX_FORM_PARTS``
parts, and file parts are spooled to disk. Anything over answers 413.

JSON
----
``request.get_json()`` / ``request.json`` check the document before parsing
it, on every route and also when the view passes ``silent=True``: nesting
deeper than :data:`MAX_JSON_DEPTH` (32) answers 400, more than
:data:`MAX_JSON_VALUES` (200,000) arrays, objects and elements answers 413.
:func:`loads_limited` applies the same checks to JSON taken from a form field.
"""

from __future__ import annotations

import json
import re
from urllib.parse import parse_qsl

from flask import Request, current_app, has_app_context, request
from flask import json as flask_json
from werkzeug.exceptions import BadRequest, RequestEntityTooLarge
from werkzeug.formparser import FormDataParser
from werkzeug.wsgi import LimitedStream

MiB = 1024 * 1024

# The body limit of every route not listed in ROUTE_BODY_LIMITS (config REQUEST_BODY_LIMIT).
DEFAULT_BODY_LIMIT = 1 * MiB

# Routes whose body may exceed the default, by Flask endpoint, for authenticated requests.
ROUTE_BODY_LIMITS = {
    # Decision-log transcripts (JSONL) up to the 32 MiB transcript limit.
    "api.upload_decision_log": 32 * MiB,
    # Audit-chain verification with up to 10,000 published chain heads.
    "api.verify_audit_log": 8 * MiB,
    # Evidence files: multipart in the admin UI, base64 in JSON through the API.
    "admin.evidence_upload": 32 * MiB,
    "api.record_execution": 32 * MiB,
    "api.batch_record_execution": 32 * MiB,
    "api.batch_submit_evidence": 32 * MiB,
    "crud.create_evidence": 32 * MiB,
    "crud.update_evidence": 32 * MiB,
}

MAX_JSON_DEPTH = 32
MAX_JSON_VALUES = 200_000

_METHODS_WITHOUT_BODY = frozenset({"GET", "HEAD", "OPTIONS"})
# Outside strings: the next character that matters to the structure.
_JSON_STRUCTURAL = re.compile(r'["\[\]{},]')
# The rest of a string literal after its opening quote, up to and including the
# closing quote. Possessive quantifiers: no backtracking, linear in its length.
_JSON_STRING_REST = re.compile(r'(?:[^"\\]++|\\.)*+"', re.DOTALL)


def default_body_limit() -> int | None:
    """The body limit of a route without an entry in :data:`ROUTE_BODY_LIMITS`."""
    if not has_app_context():
        return DEFAULT_BODY_LIMIT
    limits = [value for value in (current_app.config.get("REQUEST_BODY_LIMIT", DEFAULT_BODY_LIMIT),
                                  current_app.config.get("MAX_CONTENT_LENGTH")) if value is not None]
    return min(limits) if limits else None


# ----- JSON -----

def check_json_limits(text: str, *, max_depth: int = MAX_JSON_DEPTH, max_values: int | None = MAX_JSON_VALUES) -> None:
    """Refuse a JSON document nested deeper than ``max_depth`` (400) or with
    more than ``max_values`` arrays, objects and elements (413; None: no
    count limit), without parsing it. The defaults are MAX_JSON_DEPTH and
    MAX_JSON_VALUES.

    One left-to-right pass, linear in the length of ``text`` whatever it
    contains: string literals are skipped by a regular expression without
    backtracking, and the scan stops at the first limit exceeded. An
    unterminated string ends the scan (the parser then rejects the document).
    """
    limit = max_values if max_values is not None else float("inf")
    too_many = RequestEntityTooLarge(f"The JSON body has more than {max_values} values.")
    values = closers = depth = 0
    position, length = 0, len(text)
    while position < length:
        found = _JSON_STRUCTURAL.search(text, position)
        if found is None:
            return
        char, position = found.group(), found.end()
        if char == '"':
            rest = _JSON_STRING_REST.match(text, position)
            if rest is None:
                return
            position = rest.end()
        elif char in "[{":
            values += 1
            depth += 1
            if depth > max_depth:
                raise BadRequest(f"The JSON body is nested deeper than {max_depth} levels.")
            if values > limit:
                raise too_many
        elif char == ",":
            values += 1
            if values > limit:
                raise too_many
        else:
            closers += 1
            depth -= 1
            if closers > limit:
                raise too_many


def loads_limited(data, *, parse=None, **kwargs):
    """``json.loads`` after :func:`check_json_limits`; bytes are decoded as ``json.loads`` would.

    ``parse`` is the parser to use (default ``flask.json.loads``). Raises
    ``BadRequest`` / ``RequestEntityTooLarge`` for a document over the limits
    and ``ValueError`` for one that is not valid JSON.
    """
    if isinstance(data, (bytes, bytearray)):
        data = bytes(data).decode(json.detect_encoding(data), "surrogatepass")
    check_json_limits(data)
    try:
        return (parse or flask_json.loads)(data, **kwargs)
    except RecursionError:
        raise BadRequest(f"The JSON body is nested deeper than {MAX_JSON_DEPTH} levels.") from None


class LimitedJSON:
    """A request's ``json_module``: parsing goes through :func:`loads_limited`
    with the app's JSON provider (Flask assigns ``app.json`` to every request)."""

    def __init__(self, provider=None):
        self._provider = provider if provider is not None else flask_json

    def loads(self, data, **kwargs):
        return loads_limited(data, parse=self._provider.loads, **kwargs)

    def dumps(self, obj, **kwargs):
        return self._provider.dumps(obj, **kwargs)


# ----- forms -----

class BoundedFormDataParser(FormDataParser):
    """Applies ``max_form_memory_size`` and ``max_form_parts`` to urlencoded bodies too."""

    def _parse_urlencoded(self, stream, mimetype, content_length, options):
        limit = self.max_form_memory_size
        if limit is not None and content_length is not None and content_length > limit:
            raise RequestEntityTooLarge()
        data = stream.read() if limit is None else stream.read(limit + 1)
        if limit is not None and len(data) > limit:
            raise RequestEntityTooLarge()
        if self.max_form_parts is not None and data.count(b"&") >= self.max_form_parts:
            raise RequestEntityTooLarge()
        items = parse_qsl(data.decode(), keep_blank_values=True, errors="werkzeug.url_quote")
        return stream, self.cls(items), self.cls()


# ----- request -----

class LimitedRequest(Request):
    """The application's request class: body, form and JSON limits of this module."""

    form_data_parser_class = BoundedFormDataParser
    _json_provider = None

    @property
    def json_module(self) -> LimitedJSON:
        return LimitedJSON(self._json_provider)

    @json_module.setter
    def json_module(self, value) -> None:
        self._json_provider = value

    @property
    def max_content_length(self) -> int | None:
        if self._max_content_length is not None:
            return self._max_content_length
        return default_body_limit()

    @max_content_length.setter
    def max_content_length(self, value: int | None) -> None:
        self._max_content_length = value

    def get_data(self, cache=True, as_text=False, parse_form_data=False):
        """``Request.get_data`` that answers 413 for a streamed body over the limit.

        Werkzeug stops reading a body without a Content-Length at the limit and
        returns what it read; a body that continues past the limit is refused
        here instead of being truncated.
        """
        data = super().get_data(cache=cache, as_text=as_text, parse_form_data=parse_form_data)
        stream = self.__dict__.get("stream")
        if (isinstance(stream, LimitedStream) and stream.is_exhausted and self.content_length is None
                and self.environ["wsgi.input"].read(1)):
            raise RequestEntityTooLarge()
        return data


def _authenticated() -> bool:
    from app.auth import current_member

    member, _via_header = current_member()
    return member is not None and not member.is_expired


def apply_route_body_limit():
    """First ``before_request`` hook: apply the route's raised limit to an authenticated request."""
    raised = ROUTE_BODY_LIMITS.get(request.endpoint)
    if raised is None or request.method in _METHODS_WITHOUT_BODY:
        return None
    ceiling = current_app.config.get("MAX_CONTENT_LENGTH")
    limit = raised if ceiling is None else min(raised, ceiling)
    default = default_body_limit()
    if default is not None and limit > default and not _authenticated():
        return None
    request.max_content_length = limit
    return None


def register_request_limits(app) -> None:
    """Install the request class and the limit hook; call before any other hook is registered."""
    app.request_class = LimitedRequest
    app.before_request_funcs.setdefault(None, []).insert(0, apply_route_body_limit)


def check_route_limits(app) -> None:
    """Refuse to start when ROUTE_BODY_LIMITS names an endpoint the app does not have."""
    unknown = sorted(set(ROUTE_BODY_LIMITS) - set(app.view_functions))
    if unknown:
        raise RuntimeError(f"ROUTE_BODY_LIMITS names unknown endpoints: {', '.join(unknown)}")
