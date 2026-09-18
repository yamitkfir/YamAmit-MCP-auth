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

Two rules govern *where* we look:

* **Path insertion, not origin-only.** Both RFC 9728 §3.1 and RFC 8414 §3.1 insert the
  well-known suffix *between host and path* — a resource at `https://ex.com/public/mcp`
  publishes its PRM at `https://ex.com/.well-known/oauth-protected-resource/public/mcp`.
  Probing only the bare origin (the previous behaviour) misses it, and since the canonical
  MCP endpoint form is `https://host/mcp`, that meant missing it on essentially every real
  remote server — reporting fully compliant servers as missing their metadata.

* **Destinations are validated.** Every URL past the first hop is chosen by the server
  being scanned, so each one goes through `is_ssrf_risk` before it is fetched. Without
  that, a hostile target can aim the scanner at cloud-metadata services, at hosts on the
  operator's LAN, or at an unrelated third party. RFC 9728 §7.7 asks for exactly this.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit

from .netguard import ssrf_reason

# Cap on how many authorization servers we will chase, so a hostile PRM listing hundreds
# of entries cannot amplify one scan into a flood against a third party.
MAX_AUTHORIZATION_SERVERS = 5


@dataclass
class OAuthDiscovery:
    """Everything the OAuth detectors need, fetched once. All fields read-only."""

    attempted: bool = False

    # Protected Resource Metadata (RFC 9728)
    prm_url: str = ""
    prm_status: int | None = None
    prm: dict | None = None
    prm_source: str = ""              # "www-authenticate" | "path-inserted" | "origin"
    authorization_servers: list[str] = field(default_factory=list)
    resource_mismatch: bool = False   # PRM `resource` does not identify the scan target

    # Authorization Server Metadata (RFC 8414) — first one successfully resolved
    as_issuer: str = ""               # the issuer URL we resolved metadata for
    as_metadata_url: str = ""         # the well-known URL that answered
    as_metadata_status: int | None = None
    as_metadata: dict | None = None   # the parsed metadata document
    as_metadata_source: str = ""      # "prm-listed" | "origin-fallback"
    issuer_mismatch: bool = False     # RFC 8414 §3.3: returned issuer != requested

    # Authorization servers we were told about but did not resolve, and why.
    unresolved_servers: list[str] = field(default_factory=list)
    blocked_urls: list[str] = field(default_factory=list)   # refused by the SSRF guard
    external_hosts: list[str] = field(default_factory=list)  # contacted, not the target

    notes: list[str] = field(default_factory=list)

    @property
    def has_as_metadata(self) -> bool:
        return isinstance(self.as_metadata, dict) and bool(self.as_metadata)

    @property
    def as_metadata_usable(self) -> bool:
        """AS metadata that may be *relied on*.

        RFC 8414 §3.3 says metadata whose `issuer` does not match the requested issuer
        MUST NOT be used. Detectors #9/#11/#12 previously kept reading (and #12 kept
        *writing to*) a document that #10 had already declared unusable — one report
        contradicting itself. This is the single predicate they all consult.
        """
        return self.has_as_metadata and not self.issuer_mismatch


def is_ssrf_risk(url: str, target_url: str) -> str:
    """Why `url` must not be fetched during a scan of `target_url`, or `""` if it is fine.

    Thin re-export of the shared destination guard so discovery code and its tests have
    one obvious name to reach for.
    """
    return ssrf_reason(url, target_url)


def _origin(url: str) -> str:
    p = urlsplit(url)
    return urlunsplit((p.scheme, p.netloc, "", "", ""))


def _insert_well_known(url: str, suffix: str) -> str:
    """Build `{scheme}://{host}/.well-known/{suffix}{path}` for a resource URL."""
    p = urlsplit(url)
    path = p.path.rstrip("/")  # RFC 9728 §3.1: drop a terminating slash first
    return urlunsplit((p.scheme, p.netloc, f"/.well-known/{suffix}{path}", "", ""))


def prm_candidates(resource_url: str) -> list[str]:
    """PRM URLs to try for an MCP endpoint, in RFC 9728 §3.1 order.

    The path-inserted form comes first because that is what the RFC prescribes for a
    resource hosted at a path. The bare-origin form is kept as a second attempt: plenty of
    real servers publish there regardless, and for a bare-origin resource the two collapse
    into one URL anyway.
    """
    inserted = _insert_well_known(resource_url, "oauth-protected-resource")
    origin_form = f"{_origin(resource_url)}/.well-known/oauth-protected-resource"
    return [inserted] if inserted == origin_form else [inserted, origin_form]


def as_metadata_candidates(issuer: str) -> list[str]:
    """Well-known URLs to try for an issuer, in RFC-prescribed order.

    Per RFC 8414 §3.1 the suffix is INSERTED between the host and the path
    component (any trailing '/' on the issuer path is dropped first). Per §5,
    if that fails we fall back to the OpenID-Connect *appended* form. We also try
    the inserted `openid-configuration` form, which RFC 8414 §5 treats as a
    general OAuth feature (not OIDC-specific).

    Trying the OIDC forms is not merely a courtesy: since MCP revision 2026-07-28 an
    authorization server satisfies discovery with *either* RFC 8414 **or** OpenID Connect
    Discovery, so a server offering only the latter is compliant.
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


async def _guarded_get(probe, url: str, target_url: str, disc: OAuthDiscovery):
    """GET `url` only if the destination guard allows it. Returns the result or None."""
    reason = is_ssrf_risk(url, target_url)
    if reason:
        disc.blocked_urls.append(url)
        disc.notes.append(f"REFUSED to fetch {url}: {reason}")
        return None
    host = (urlsplit(url).hostname or "").lower()
    target_host = (urlsplit(target_url).hostname or "").lower()
    if host and host != target_host and host not in disc.external_hosts:
        disc.external_hosts.append(host)
    return await probe.request("GET", url)


def _record_fetch(disc: OAuthDiscovery, label: str, url: str, res) -> None:
    """Append one auditable line about a discovery fetch, naming where we ended up."""
    if res is None:
        return
    if not res.ok:
        kind = "TLS/certificate error" if res.tls_failure else "transport error"
        disc.notes.append(f"{label} GET {url} -> {kind}: {res.error}")
        return
    where = ""
    if res.final_url and res.final_url != url:
        where = f" [redirect to {res.final_url} NOT followed]"
    disc.notes.append(f"{label} GET {url} -> HTTP {res.status}{where}")


async def _fetch_as_metadata(
    probe, issuer: str, source: str, disc: OAuthDiscovery, target_url: str
) -> bool:
    """Try each candidate URL for `issuer`; on first hit, populate `disc`. Returns hit."""
    for url in as_metadata_candidates(issuer):
        res = await _guarded_get(probe, url, target_url, disc)
        if res is None:
            continue
        _record_fetch(disc, "AS metadata", url, res)
        if not res.ok:
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
                        f"{returned!r} (RFC 8414 §3.3 says such metadata MUST NOT be used, "
                        "so no other detector will rely on it)."
                    )
                else:
                    disc.notes.append(
                        f"AS metadata at {url} declares issuer {returned!r} (we probed the "
                        f"origin {issuer!r} as a fallback; not treated as a mismatch)."
                    )
            disc.notes.append(f"AS metadata resolved at {url} (source={source}).")
            return True
    return False


def _prm_hint_from_challenge(www_authenticate: str) -> str:
    """Extract the `resource_metadata="..."` URL from a WWW-Authenticate challenge.

    RFC 9728 §5.1 makes this the *authoritative* PRM location, and the MCP spec makes
    using it a client MUST. Guessing the URL instead — while detector #3 parses this very
    header in the same scan — meant the scanner failed the requirement it audits.
    """
    for chunk in www_authenticate.replace(",", " ").split():
        if chunk.lower().startswith("resource_metadata="):
            return chunk.split("=", 1)[1].strip().strip('"\'')
    return ""


async def discover_oauth(probe, target_url: str, www_authenticate: str = "") -> OAuthDiscovery:
    """Fetch the PRM → Authorization-Server-Metadata chain for an MCP target.

    Never raises. Always returns a populated `OAuthDiscovery` (with notes explaining
    whatever could not be resolved) so detectors can render honest verdicts.
    """
    disc = OAuthDiscovery(attempted=True)
    origin = _origin(target_url)

    # 1) Protected Resource Metadata (RFC 9728). Prefer the authoritative pointer from a
    #    401 challenge, then the path-inserted well-known URL, then the bare origin.
    candidates: list[tuple[str, str]] = []
    hint = _prm_hint_from_challenge(www_authenticate) if www_authenticate else ""
    if hint:
        candidates.append((hint, "www-authenticate"))
    for i, url in enumerate(prm_candidates(target_url)):
        candidates.append((url, "path-inserted" if i == 0 else "origin"))

    for url, source in candidates:
        if disc.prm is not None:
            break
        res = await _guarded_get(probe, url, target_url, disc)
        if res is None:
            continue
        _record_fetch(disc, "PRM", url, res)
        if not res.ok:
            continue
        disc.prm_url, disc.prm_status = url, res.status
        if res.status == 200 and isinstance(res.json, dict):
            disc.prm = res.json
            disc.prm_source = source
            disc.authorization_servers = _clean_authorization_servers(res.json, disc)
            disc.resource_mismatch = _resource_mismatches(res.json, target_url, disc)
            disc.notes.append(
                f"PRM found at {url} (source={source}): "
                f"{len(disc.authorization_servers)} authorization_servers."
            )

    if disc.prm is None:
        disc.notes.append(
            "No usable RFC 9728 Protected Resource Metadata document "
            f"(tried: {', '.join(u for u, _ in candidates)})."
        )

    # 2) Authorization Server Metadata. Prefer PRM-listed servers; first hit wins, but
    #    record the ones we never got to so the report cannot imply they were cleared.
    for i, issuer in enumerate(disc.authorization_servers):
        if await _fetch_as_metadata(probe, issuer, "prm-listed", disc, target_url):
            # EXTEND, don't replace: servers earlier in the list that we tried and failed to
            # resolve are already recorded here. Overwriting dropped them from the report
            # entirely, so a server that had been tried and failed appeared neither examined
            # nor unexamined — the precise implication this field exists to prevent.
            disc.unresolved_servers += disc.authorization_servers[i + 1:]
            if disc.unresolved_servers:
                disc.notes.append(
                    f"{len(disc.unresolved_servers)} other advertised authorization "
                    f"server(s) were not resolved (either tried without success or never "
                    f"attempted): {disc.unresolved_servers}. Verdicts below describe only "
                    f"{issuer}, the one that resolved."
                )
            return disc
        disc.unresolved_servers.append(issuer)

    # 3) Fallback: many MCP servers ARE their own authorization server. Try the
    #    target's own origin so gaps 9–12 stay testable even when PRM is absent.
    if not disc.has_as_metadata:
        if await _fetch_as_metadata(probe, origin, "origin-fallback", disc, target_url):
            return disc
        disc.notes.append("No Authorization Server Metadata resolved (PRM or origin).")

    return disc


def _clean_authorization_servers(prm: dict, disc: OAuthDiscovery) -> list[str]:
    """Validate the `authorization_servers` field before we act on it.

    The value comes from a document the target controls, so it needs type checking: a bare
    JSON string used to be iterated *character by character* (producing nonsense fetches
    and a fabricated verdict), and a scalar crashed the whole scan. A hostile long list is
    also capped, since each entry costs up to three requests against a third party.
    """
    raw = prm.get("authorization_servers")
    if raw is None:
        return []
    if not isinstance(raw, list):
        disc.notes.append(
            f"PRM `authorization_servers` is {type(raw).__name__}, not a list "
            "(RFC 9728 requires an array) — ignoring the field."
        )
        return []
    servers = [str(s).strip() for s in raw if isinstance(s, str) and str(s).strip()]
    if len(servers) != len(raw):
        disc.notes.append(
            f"PRM `authorization_servers` had {len(raw) - len(servers)} non-string / "
            "empty entr(ies), which were ignored."
        )
    if len(servers) > MAX_AUTHORIZATION_SERVERS:
        disc.notes.append(
            f"PRM advertises {len(servers)} authorization servers; only the first "
            f"{MAX_AUTHORIZATION_SERVERS} are examined (flood guard)."
        )
        servers = servers[:MAX_AUTHORIZATION_SERVERS]
    return servers


def _resource_mismatches(prm: dict, target_url: str, disc: OAuthDiscovery) -> bool:
    """RFC 9728 §3.3: the PRM's `resource` must identify the resource we asked about.

    A document that describes some *other* resource tells us nothing about this target, so
    silently accepting it would attribute another server's posture to this one.
    """
    resource = prm.get("resource")
    if not isinstance(resource, str) or not resource:
        disc.notes.append("PRM has no string `resource` field (RFC 9728 §3.3 requires it).")
        return False
    if resource.rstrip("/") == target_url.rstrip("/"):
        return False
    same_host = (urlsplit(resource).hostname or "").lower() == (
        urlsplit(target_url).hostname or ""
    ).lower()
    disc.notes.append(
        f"PRM `resource` is {resource!r} but we scanned {target_url!r}"
        + ("" if same_host else " — a DIFFERENT host, so this document may describe "
                               "another resource entirely")
        + "."
    )
    return not same_host
