"""Outbound HTTP requests that cannot reach internal addresses (SSRF protection).

Every request the portal makes to an address an administrator or team member
configured (vendor pages, platform health checks, the GitHub API) goes
through :func:`safe_get`:

- Only ``http`` and ``https`` URLs with a host and without credentials in the
  URL are accepted.
- The host is resolved with ``socket.getaddrinfo`` and the request is refused
  when ANY address it resolves to is loopback, private (RFC 1918, unique
  local ``fc00::/7``), shared (``100.64.0.0/10``), link-local
  (``169.254.0.0/16``, ``fe80::/10``), multicast, reserved, unspecified or
  otherwise not globally routable, or a cloud metadata endpoint
  (:data:`METADATA_ADDRESSES`, e.g. ``169.254.169.254`` and
  ``fd00:ec2::254``). An IPv6 address that embeds an IPv4 address
  (IPv4-mapped ``::ffff:0:0/96``, NAT64 ``64:ff9b::/96``, 6to4 ``2002::/16``,
  IPv4-compatible ``::/96``) is judged by the IPv4 address it carries.
- Redirects are followed manually, at most ``max_redirects`` of them, and
  every hop is checked the same way. ``Authorization`` and ``auth`` are sent
  only to the origin (scheme, host and port) of the original URL.
- Sessions made by :func:`guarded_session` (the default) also check the
  address each socket actually connected to, so a name that re-resolves to an
  internal address after the check (DNS rebinding) is refused as well.
- Guarded requests never use a proxy: ``HTTP_PROXY``, ``HTTPS_PROXY``,
  ``ALL_PROXY`` and ``.netrc`` are ignored (the session does not trust the
  environment, and :func:`safe_get` disables proxies on any session it is
  given), so every connection goes to the checked address itself.
  ``REQUESTS_CA_BUNDLE`` / ``CURL_CA_BUNDLE`` still select the CA bundle.

``allow_private=True`` admits private, shared and loopback addresses, for
health checks of an organisation's own internal services; link-local,
multicast, reserved and unspecified addresses and the cloud metadata
endpoints stay refused.

A refused request raises :class:`UnsafeURLError` (a ``ValueError``) whose
message starts with ``refused`` and names the host and the reason; more than
``max_redirects`` redirects raise ``requests.TooManyRedirects``.
"""

from __future__ import annotations

import ipaddress
import os
import socket
from urllib.parse import urljoin, urlsplit

import requests
from requests.adapters import HTTPAdapter
from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool

ALLOWED_SCHEMES = ("http", "https")
DEFAULT_PORTS = {"http": 80, "https": 443}
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
# Per-request proxies that override every proxy from the session or the environment.
NO_PROXIES = {"http": None, "https": None, "all": None}

# Instance and task metadata / credential endpoints of the major clouds.
METADATA_ADDRESSES = frozenset(ipaddress.ip_address(address) for address in (
    "169.254.169.254",   # AWS, Azure, GCP and others: instance metadata
    "169.254.170.2",     # AWS ECS task metadata and credentials
    "169.254.170.23",    # AWS EKS pod identity
    "fd00:ec2::254",     # AWS instance metadata over IPv6
    "fd00:ec2::23",      # AWS EKS pod identity over IPv6
    "100.100.100.200",   # Alibaba Cloud metadata
    "192.0.0.192",       # Oracle Cloud metadata
    "168.63.129.16",     # Azure platform (WireServer)
))

_SHARED_V4 = ipaddress.ip_network("100.64.0.0/10")
_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_IPV4_COMPATIBLE = ipaddress.ip_network("::/96")
# Reasons ``allow_private`` admits.
_PRIVATE_REASONS = frozenset({"private", "shared", "loopback"})


class UnsafeURLError(ValueError):
    """The URL is not an http(s) URL or leads to an address the portal must not contact."""


def _embedded_ipv4(ip: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    if ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    if ip.sixtofour is not None:
        return ip.sixtofour
    if ip in _NAT64 or (ip in _IPV4_COMPATIBLE and int(ip) > 1):
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    return None


def refusal_reason(address: str, *, allow_private: bool = False) -> str | None:
    """Why the portal must not connect to ``address`` (an IP literal), or None when it may."""
    try:
        ip = ipaddress.ip_address(address.split("%", 1)[0])
    except ValueError:
        return "invalid"
    if ip in METADATA_ADDRESSES:
        return "cloud metadata"
    if isinstance(ip, ipaddress.IPv6Address):
        embedded = _embedded_ipv4(ip)
        if embedded is not None:
            reason = refusal_reason(str(embedded), allow_private=allow_private)
            if reason or ip.ipv4_mapped is not None or ip in _NAT64:
                return reason
    if ip.is_unspecified:
        reason = "unspecified"
    elif ip.is_loopback:
        reason = "loopback"
    elif ip.is_link_local:
        reason = "link-local"
    elif ip.is_multicast:
        reason = "multicast"
    elif ip.is_reserved:
        reason = "reserved"
    elif isinstance(ip, ipaddress.IPv4Address) and ip in _SHARED_V4:
        reason = "shared"
    elif ip.is_private:
        reason = "private"
    elif not ip.is_global:
        reason = "non-public"
    else:
        return None
    if allow_private and reason in _PRIVATE_REASONS:
        return None
    return reason


def check_url(url: str, *, allow_private: bool = False) -> list[str]:
    """Validate ``url`` and resolve its host; returns the addresses, or raises UnsafeURLError."""
    if not isinstance(url, str) or not url:
        raise UnsafeURLError(f"refused {url!r}: not a URL")
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError as exc:
        raise UnsafeURLError(f"refused {url!r}: {exc}") from None
    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise UnsafeURLError(f"refused {url!r}: only http and https URLs are allowed")
    host = parts.hostname
    if not host:
        raise UnsafeURLError(f"refused {url!r}: the URL has no host")
    if parts.username is not None or parts.password is not None:
        raise UnsafeURLError(f"refused {host}: credentials in the URL are not allowed")
    try:
        infos = socket.getaddrinfo(host, port or DEFAULT_PORTS[scheme], type=socket.SOCK_STREAM)
    except (OSError, UnicodeError):
        raise UnsafeURLError(f"refused {host}: the name could not be resolved") from None
    addresses = sorted({info[4][0] for info in infos})
    if not addresses:
        raise UnsafeURLError(f"refused {host}: the name could not be resolved")
    for address in addresses:
        reason = refusal_reason(address, allow_private=allow_private)
        if reason:
            raise UnsafeURLError(f"refused {host}: it resolves to {address}, a {reason} address")
    return addresses


def _check_peer(sock, host: str, allow_private: bool) -> None:
    try:
        peer = sock.getpeername()[0]
    except (OSError, IndexError, TypeError):
        peer = None
    reason = refusal_reason(peer, allow_private=allow_private) if isinstance(peer, str) else "unknown"
    if reason:
        sock.close()
        raise UnsafeURLError(f"refused {host}: connected to {peer}, a {reason} address")


class GuardedHTTPConnection(HTTPConnection):
    """An HTTP connection that refuses a socket connected to an internal address."""

    allow_private = False

    def _new_conn(self):
        sock = super()._new_conn()
        _check_peer(sock, self.host, self.allow_private)
        return sock


class GuardedHTTPSConnection(HTTPSConnection):
    """An HTTPS connection that refuses a socket connected to an internal address."""

    allow_private = False

    def _new_conn(self):
        sock = super()._new_conn()
        _check_peer(sock, self.host, self.allow_private)
        return sock


def _pool_classes(allow_private: bool) -> dict[str, type]:
    http_conn = type("GuardedHTTPConnectionPrivate" if allow_private else "GuardedHTTPConnectionPublic",
                     (GuardedHTTPConnection,), {"allow_private": allow_private})
    https_conn = type("GuardedHTTPSConnectionPrivate" if allow_private else "GuardedHTTPSConnectionPublic",
                      (GuardedHTTPSConnection,), {"allow_private": allow_private})
    return {
        "http": type("GuardedHTTPConnectionPool", (HTTPConnectionPool,), {"ConnectionCls": http_conn}),
        "https": type("GuardedHTTPSConnectionPool", (HTTPSConnectionPool,), {"ConnectionCls": https_conn}),
    }


_POOL_CLASSES = {False: _pool_classes(False), True: _pool_classes(True)}


class GuardedAdapter(HTTPAdapter):
    """A requests transport adapter whose direct connections are checked by peer address."""

    allow_private = False

    def __init__(self, *, allow_private: bool = False, **kwargs):
        self.allow_private = bool(allow_private)
        super().__init__(**kwargs)

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        super().init_poolmanager(connections, maxsize, block=block, **pool_kwargs)
        self.poolmanager.pool_classes_by_scheme = dict(_POOL_CLASSES[self.allow_private])


def guarded_session(*, allow_private: bool = False) -> requests.Session:
    """A ``requests.Session`` whose http and https connections are checked by peer address.

    It ignores proxy and ``.netrc`` settings from the environment; the CA bundle
    named by ``REQUESTS_CA_BUNDLE`` or ``CURL_CA_BUNDLE`` still applies.
    """
    session = requests.Session()
    session.trust_env = False
    session.proxies = {}
    session.verify = os.environ.get("REQUESTS_CA_BUNDLE") or os.environ.get("CURL_CA_BUNDLE") or True
    adapter = GuardedAdapter(allow_private=allow_private)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def _origin(url: str) -> tuple[str, str, int | None]:
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    return scheme, (parts.hostname or "").lower(), parts.port or DEFAULT_PORTS.get(scheme)


def release(response) -> None:
    """Close ``response`` (returning its connection to the pool), ignoring one already closed."""
    close = getattr(response, "close", None)
    if callable(close):
        try:
            close()
        except (AttributeError, OSError):
            pass


def safe_get(url: str, *, timeout, headers: dict | None = None, max_redirects: int = 5,
             allow_private: bool = False, session: requests.Session | None = None,
             params: dict | None = None, auth=None, stream: bool = False):
    """GET ``url`` after checking it and every redirect hop; returns the final response.

    ``session`` defaults to a fresh :func:`guarded_session`, closed before
    returning (a ``stream=True`` response stays readable; the caller closes
    it). ``params`` apply to the first request only; a redirect ``Location``
    is used as given.
    Raises :class:`UnsafeURLError` or ``requests.TooManyRedirects``;
    transport errors propagate as ``requests.RequestException``.
    """
    own_session = session is None
    if own_session:
        session = guarded_session(allow_private=allow_private)
    try:
        origin = _origin(url) if isinstance(url, str) else None
        current = url
        send_headers = dict(headers or {})
        send_auth = auth
        send_params = params
        redirects = 0
        while True:
            check_url(current, allow_private=allow_private)
            kwargs = {"headers": send_headers, "timeout": timeout, "allow_redirects": False}
            if getattr(session, "trust_env", False) or getattr(session, "proxies", None):
                # A session that would use a proxy (its own or the environment's) gets none.
                kwargs["proxies"] = dict(NO_PROXIES)
            if send_params:
                kwargs["params"] = send_params
            if send_auth is not None:
                kwargs["auth"] = send_auth
            if stream:
                kwargs["stream"] = True
            response = session.get(current, **kwargs)
            if response.status_code not in REDIRECT_STATUSES:
                return response
            location = response.headers.get("Location")
            if not location:
                return response
            if redirects >= max_redirects:
                release(response)
                raise requests.TooManyRedirects(f"more than {max_redirects} redirects from {url}")
            release(response)
            redirects += 1
            current = urljoin(current, location.strip())
            send_params = None
            if _origin(current) != origin:
                send_headers = {k: v for k, v in send_headers.items() if k.lower() != "authorization"}
                send_auth = None
    finally:
        if own_session:
            session.close()
