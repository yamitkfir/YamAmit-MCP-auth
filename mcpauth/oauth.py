"""OAuth metadata discovery — the shared fetch behind the Tier-2 OAuth detectors.

Gaps 9–12 (auth-endpoints-not-https, missing-as-metadata, implicit-flow-enabled,
open-dcr) all reason about the *same* two documents:

  1. Protected Resource Metadata (PRM, RFC 9728) at
     `/.well-known/oauth-protected-resource` — names the authorization server(s).
  2. Authorization Server Metadata (RFC 8414) — describes the grant types, PKCE
     methods, endpoints, and the dynamic-registration endpoint.

Fetching this chain once in the runner's discovery phase (rather than once per
detector) keeps detectors independent: each reads `ctx.oauth`, never another
detector's Finding, and we don't hammer the target with duplicate requests.

The well-known URL construction follows RFC 8414 §3.1 *exactly*: the suffix is
**inserted between host and path** (`https://as/.well-known/oauth-authorization-server/tenant`),
NOT appended OIDC-style. We try the insertion form first, then fall back to the
OpenID-Connect appended form (RFC 8414 §5). Issuer identity is checked per §3.3.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit

# Imported lazily inside functions to avoid a cycle (probe has no dep on this module).


@dataclass
class OAuthDiscovery:
    """Everything the OAuth detectors need, fetched once. All fields read-only."""

    attempted: bool = False

    # Protected Resource Metadata (RFC 9728)
    prm_url: str = ""
    prm_status: int | None = None
    prm: dict | None = None
    authorization_servers: list[str] = field(default_factory=list)

    # Authorization Server Metadata (RFC 8414) — first one successfully resolved
    as_issuer: str = ""               # the issuer URL we resolved metadata for
    as_metadata_url: str = ""         # the well-known URL that answered
    as_metadata_status: int | None = None
    as_metadata: dict | None = None   # the parsed metadata document
    as_metadata_source: str = ""      # "prm-listed" | "origin-fallback"
    issuer_mismatch: bool = False     # RFC 8414 §3.3: returned issuer != requested

    notes: list[str] = field(default_factory=list)

    @property
    def has_as_metadata(self) -> bool:
        return isinstance(self.as_metadata, dict) and bool(self.as_metadata)


def _origin(url: str) -> str:
    p = urlsplit(url)
    return urlunsplit((p.scheme, p.netloc, "", "", ""))


def as_metadata_candidates(issuer: str) -> list[str]:
    """Well-known URLs to try for an issuer, in RFC-prescribed order.

    Per RFC 8414 §3.1 the suffix is INSERTED between the host and the path
    component (any trailing '/' on the issuer path is dropped first). Per §5,
    if that fails we fall back to the OpenID-Connect *appended* form. We also try
    the inserted `openid-configuration` form, which RFC 8414 §5 treats as a
    general OAuth feature (not OIDC-specific).
    """
    p = urlsplit(issuer)
    path = p.path.rstrip("/")  # "" for a bare-origin issuer

    def build(new_path: str) -> str:
        return urlunsplit((p.scheme, p.netloc, new_path, "", ""))

    inserted_oauth = build(f"/.well-known/oauth-authorization-server{path}")
    inserted_oidc = build(f"/.well-known/openid-configuration{path}")
    appended_oidc = build(f"{path}/.well-known/openid-configuration")

    # De-dup while preserving order (bare-origin issuers collapse some of these).
    seen, ordered = set(), []
    for u in (inserted_oauth, inserted_oidc, appended_oidc):
        if u not in seen:
            seen.add(u)
            ordered.append(u)
    return ordered


async def _fetch_as_metadata(probe, issuer: str, source: str, disc: OAuthDiscovery) -> bool:
    """Try each candidate URL for `issuer`; on first hit, populate `disc`. Returns hit."""
    for url in as_metadata_candidates(issuer):
        res = await probe.request("GET", url)
        if not res.ok:
            disc.notes.append(f"AS metadata GET {url} -> transport error: {res.error}")
            continue
        if res.status == 200 and isinstance(res.json, dict) and res.json:
            disc.as_issuer = issuer
            disc.as_metadata_url = url
            disc.as_metadata_status = res.status
            disc.as_metadata = res.json
            disc.as_metadata_source = source
            returned = str(res.json.get("issuer", ""))
            # RFC 8414 §3.3: returned issuer MUST equal the *requested* issuer. This only
            # bites when the issuer was authoritative (named by the PRM). For the origin
            # fallback the "issuer" is our own guess, so a difference there is expected and
            # must NOT be reported as a violation (it would be a false positive).
            mismatch = bool(returned) and returned.rstrip("/") != issuer.rstrip("/")
            disc.issuer_mismatch = mismatch and source == "prm-listed"
            if mismatch:
                if disc.issuer_mismatch:
                    disc.notes.append(
                        f"issuer mismatch: PRM named {issuer!r} but its metadata declares "
                        f"{returned!r} (RFC 8414 §3.3 says such metadata MUST NOT be used)."
                    )
                else:
                    disc.notes.append(
                        f"AS metadata at {url} declares issuer {returned!r} (we probed the "
                        f"origin {issuer!r} as a fallback; not treated as a mismatch)."
                    )
            disc.notes.append(f"AS metadata resolved at {url} (source={source}).")
            return True
        disc.notes.append(f"AS metadata GET {url} -> HTTP {res.status} (not usable).")
    return False


async def discover_oauth(probe, target_url: str) -> OAuthDiscovery:
    """Fetch the PRM → Authorization-Server-Metadata chain for an MCP target.

    Never raises. Always returns a populated `OAuthDiscovery` (with notes explaining
    whatever could not be resolved) so detectors can render honest verdicts.
    """
    disc = OAuthDiscovery(attempted=True)
    origin = _origin(target_url)

    # 1) Protected Resource Metadata (RFC 9728), origin-based well-known.
    disc.prm_url = f"{origin}/.well-known/oauth-protected-resource"
    prm_res = await probe.request("GET", disc.prm_url)
    if prm_res.ok:
        disc.prm_status = prm_res.status
        if prm_res.status == 200 and isinstance(prm_res.json, dict):
            disc.prm = prm_res.json
            servers = prm_res.json.get("authorization_servers") or []
            disc.authorization_servers = [str(s) for s in servers if s]
            disc.notes.append(
                f"PRM at {disc.prm_url}: {len(disc.authorization_servers)} "
                "authorization_servers."
            )
        else:
            disc.notes.append(f"PRM at {disc.prm_url} -> HTTP {prm_res.status} (no usable doc).")
    else:
        disc.notes.append(f"PRM GET {disc.prm_url} -> transport error: {prm_res.error}")

    # 2) Authorization Server Metadata. Prefer PRM-listed servers; first hit wins.
    for issuer in disc.authorization_servers:
        if await _fetch_as_metadata(probe, issuer, "prm-listed", disc):
            return disc

    # 3) Fallback: many MCP servers ARE their own authorization server. Try the
    #    target's own origin so gaps 9–12 stay testable even when PRM is absent.
    if not disc.has_as_metadata:
        if await _fetch_as_metadata(probe, origin, "origin-fallback", disc):
            return disc
        disc.notes.append("No Authorization Server Metadata resolved (PRM or origin).")

    return disc
