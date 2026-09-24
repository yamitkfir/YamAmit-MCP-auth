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

Containment is enforced in **two places**, because a URL string and the machine it reaches
are different things:

1. The predicates in this module judge what a URL *says*, before it is fetched. They
   recognise an internal destination only when it is written as an IP literal.
2. `resolved_address_reason` judges what a hostname *resolved to*, and is called from the
   resolver in `probe.py` — so it runs at connect time, on the addresses actually about to
   be dialled. This is what catches a target-supplied name pointing at `127.0.0.1`, RFC
   1918 space, or `169.254.169.254`. It has to happen there rather than as a pre-flight
   lookup, or the name can be re-pointed between the check and the connection (DNS
   rebinding).

What remains deliberately permitted, stated honestly so no caller over-trusts these:

* `registrable_domain` is a two-label approximation with no public-suffix list, so every
  tenant of a shared suffix (`railway.app`, `vercel.app`, `github.io`, `co.uk`) looks like
  a sibling of every other — which widens what `same_site` permits the one write to reach.
* Unrelated *public* third parties are allowed for reads by design: following a PRM that
  names someone else's authorization server is the normal case.
* `is_loopback_host` matches a fixed spelling list, so `localhost.` and `0x7f.0.0.1` are
  not recognised as this machine *by the predicates*. Layer 2 catches them anyway, since
  both resolve to a loopback address.

Apart from `resolved_address_reason`, which is handed addresses the caller resolved,
nothing here talks to the network: these are pure predicates, unit-testable without a live
target.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from urllib.parse import urlsplit

_LOOPBACK_NAMES = ("localhost", "127.0.0.1", "::1", "[::1]")


class BlockedDestination(Exception):
    """A hostname resolved to an address the scanner must not contact.

    Raised from the resolver so it aborts the connection, rather than reporting on one that
    already happened. Deliberately **not** an `OSError`: aiohttp wraps those in
    `ClientConnectorError`, whose message interpolates "Cannot connect to host" and
    "ssl:default", which would bury the real reason inside text that
    `probe._is_tls_failure` inspects.
    """


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
    unique-local IPv6, multicast, reserved, the unspecified address, and anything else IANA
    reserves for a special purpose (see the `is_global` catch-all below, which is what picks
    up carrier-grade NAT).

    Loopback *names* are included because `http://localhost:6379` reaches exactly the same
    service as `http://127.0.0.1:6379`; judging only IP literals would leave the guard
    trivially bypassable by spelling. Other DNS names are not resolved here — this is a pure
    predicate — so a name pointing into private space is not caught *by this function*. It is
    caught by `resolved_address_reason`, which is handed the resolved addresses at connect
    time; the two together are what make the module's promise hold.
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
        # Catch-all for everything else IANA reserves for a special purpose. The named
        # checks above miss carrier-grade NAT (`100.64.0.0/10`), which Python reports as
        # neither private nor reserved, yet is routable inside an ISP or a container
        # network rather than on the public internet. `is_global` is the complement of the
        # special-purpose registry, so no genuinely public address is refused by it.
        or not ip.is_global
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
    unrelated party or into private address space *written as an IP literal*. Two caveats
    from the module docstring apply here and are not enforced: a sibling name that resolves
    into private space is permitted, and on a shared hosting suffix every unrelated tenant
    counts as a sibling.
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


def resolved_address_reason(
    host: str, addresses: Iterable[str], target_host: str
) -> str:
    """Why a connection to `host` must be aborted, or `""` if it may proceed.

    Layer 2 of the containment described in the module docstring: `addresses` are what
    `host` just resolved to, so this sees through a name that the string-only predicates
    above cannot judge. `https://intranet.example.com/register` is indistinguishable from
    any other public URL until this point.

    The scan target's own host keeps the same exemption `ssrf_reason` gives it — the
    operator asked us to talk to that machine, and scanning a local sandbox depends on it.
    The exemption is scoped to that one host: a loopback target must not be able to point us
    at the rest of the private address space, which is why every *other* name is judged on
    the addresses it resolved to regardless of how local the target is.

    A name resolving to several addresses is refused if **any** of them is internal. A
    split-horizon name with one public and one private answer would otherwise be a coin
    flip decided by resolver ordering.
    """
    if _same_host(host.lower(), (target_host or "").lower()):
        return ""
    internal = sorted({a for a in addresses if is_internal_host(a)})
    if not internal:
        return ""
    return (
        f"{host!r} resolves to internal address {', '.join(internal)} (loopback / private / "
        f"link-local) and is not the scan target {target_host!r} — aborting the connection"
    )
