"""Destination classification — the containment layer for target-supplied URLs.

Almost every URL this tool fetches after the first one is *chosen by the server being
scanned*: `authorization_servers` in its Protected Resource Metadata, the endpoint URLs in
its Authorization Server Metadata, its `registration_endpoint`, the
`registration_client_uri` it hands back, and the `resource_metadata` pointer in its 401.

Following those blindly makes the scanner a confused deputy (a trusted program tricked
into misusing its powers): a hostile or merely misconfigured target can aim our requests —
including the one *write* we perform — at a cloud metadata service, at a service on the
operator's own LAN, or at an unrelated third party who never agreed to be scanned. MCP
Security Best Practices and RFC 9728 §7.7 both call for blocking exactly this.

Nothing here talks to the network; these are pure predicates so they can be unit-tested
without a live target.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit

_LOOPBACK_NAMES = ("localhost", "127.0.0.1", "::1", "[::1]")


def is_loopback_host(host: str) -> bool:
    """True for a host reachable only from this machine (`localhost` / `127.0.0.1` / `::1`).

    Cleartext http and missing TLS are acceptable on loopback, so several gaps exempt it.
    """
    h = (host or "").lower().strip("[]")
    if h in _LOOPBACK_NAMES or h.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


def host_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Parse `host` as a literal IP address, or None if it is a DNS name."""
    try:
        return ipaddress.ip_address((host or "").strip("[]"))
    except ValueError:
        return None


def is_internal_host(host: str) -> bool:
    """True if `host` names a destination we must never fetch from.

    Covers loopback (`127.0.0.0/8`, `::1`, and the *name* `localhost`), private/RFC 1918
    space (`10/8`, `172.16/12`, `192.168/16`), link-local — which includes the
    `169.254.169.254` cloud metadata service that hands out machine credentials —
    unique-local IPv6, multicast, reserved, and the unspecified address.

    Loopback *names* are included because `http://localhost:6379` reaches exactly the same
    service as `http://127.0.0.1:6379`; judging only IP literals would leave the guard
    trivially bypassable by spelling. Other DNS names are not resolved here — that is the
    caller's job — so a name pointing into private space is not caught by this predicate
    alone.
    """
    if is_loopback_host(host):
        return True
    ip = host_ip(host)
    if ip is None:
        return False
    return bool(
        ip.is_loopback
        or ip.is_private
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def registrable_domain(host: str) -> str:
    """The 'same organisation' key for a hostname: its last two labels.

    `mcp.example.com` and `auth.example.com` share `example.com`, so metadata on one
    naming the other is normal OAuth practice. `mcp.example.com.evil.test` yields
    `evil.test`, so the classic suffix-spoofing trick does not pass. Literal IPs and
    single-label names are returned unchanged (they have no parent to share).

    This is a deliberate approximation: a real public-suffix list would also stop
    `foo.co.uk` matching `bar.co.uk`. We accept that, because the check is a *containment*
    guard for writes, not an authentication decision, and the operator can always name an
    external host explicitly.
    """
    h = (host or "").lower().rstrip(".")
    if not h or host_ip(h) is not None:
        return h
    labels = h.split(".")
    if len(labels) < 2:
        return h
    return ".".join(labels[-2:])


def same_site(url: str, target_url: str) -> bool:
    """True if `url` belongs to the same organisation as the scan target.

    Used to contain the one detector that writes (`open-dcr`): a registration POST may go
    to the target itself or to a sibling host under the same registrable domain (many MCP
    servers put their authorization server on `auth.<same-domain>`), but never to an
    unrelated party or into private address space.
    """
    u, t = urlsplit(url), urlsplit(target_url)
    uh, th = (u.hostname or "").lower(), (t.hostname or "").lower()
    if not uh or not th:
        return False
    if is_internal_host(uh) and uh != th:
        return False
    if uh == th:
        return True
    return registrable_domain(uh) == registrable_domain(th)


def ssrf_reason(url: str, target_url: str) -> str:
    """Why `url` must not be fetched, or `""` if fetching it is allowed.

    The scan target's own host is always allowed — that is the thing the operator asked us
    to talk to, and it is how scanning a local sandbox keeps working. That exemption is
    scoped to *that host only*: a target on `127.0.0.1` must not be able to redirect us
    into the rest of the private address space, so every other internal destination stays
    blocked even for a loopback target.
    """
    parts = urlsplit(url)
    scheme, host = parts.scheme.lower(), (parts.hostname or "").lower()
    if not host:
        return f"{url!r} has no host to fetch"
    if scheme not in ("http", "https"):
        return f"{url!r} uses scheme {scheme!r}; only http/https are fetched"

    target_host = (urlsplit(target_url).hostname or "").lower()
    if _same_host(host, target_host):
        return ""

    if is_internal_host(host):
        return (
            f"{url!r} points at internal address {host!r} (loopback / private / "
            "link-local), which is not the scan target — refusing to fetch"
        )
    return ""


def _same_host(host: str, target_host: str) -> bool:
    """Host equality that treats `localhost` and `127.0.0.1` as the same machine."""
    if not host or not target_host:
        return False
    if host == target_host:
        return True
    return is_loopback_host(host) and is_loopback_host(target_host)
