"""Privacy-preserving serialization for bounded HTTP observations."""

from __future__ import annotations

from hashlib import sha256
from collections.abc import Callable
from typing import Protocol
from urllib.parse import urlsplit, urlunsplit


class HTTPObservationLike(Protocol):
    url: str
    method: str
    status_code: int
    reason: str
    headers: tuple[tuple[str, str], ...]
    body_excerpt: str
    redirect_location: str | None


_SAFE_RESPONSE_HEADERS = frozenset(
    {
        "content-security-policy",
        "content-type",
        "permissions-policy",
        "referrer-policy",
        "server",
        "set-cookie",
        "strict-transport-security",
        "x-content-type-options",
        "x-frame-options",
    }
)
_MAX_PERSISTED_HEADERS = 16
_MAX_PERSISTED_HEADER_VALUE_CHARS = 512


def safe_http_evidence_url(url: str) -> str:
    """Remove URL credentials and request-specific data from persisted evidence."""
    parsed = urlsplit(url)
    authority = parsed.netloc.rsplit("@", 1)[-1]
    return urlunsplit((parsed.scheme, authority, parsed.path, "", ""))


def redirect_was_observed(observation: HTTPObservationLike) -> bool:
    return observation.redirect_location is not None or any(
        name.lower() == "location" for name, _ in observation.headers
    )


def safe_content_type(value: str) -> str:
    """Keep the media type while dropping arbitrary response parameters."""
    return value.split(";", maxsplit=1)[0].strip()[:_MAX_PERSISTED_HEADER_VALUE_CHARS]


def serialize_http_evidence(
    observation: HTTPObservationLike,
    *,
    cookie_redactor: Callable[[str], str],
    body_truncated: bool = False,
) -> str:
    """Keep useful response metadata without persisting bodies or arbitrary headers."""
    selected_headers = [
        (name, value)
        for name, value in observation.headers
        if name.lower() in _SAFE_RESPONSE_HEADERS
    ]
    safe_headers = []
    for name, value in selected_headers[:_MAX_PERSISTED_HEADERS]:
        safe_value = cookie_redactor(value) if name.lower() == "set-cookie" else value
        if name.lower() == "content-type":
            safe_value = safe_content_type(safe_value)
        safe_headers.append(f"{name}: {safe_value[:_MAX_PERSISTED_HEADER_VALUE_CHARS]}")
    body = observation.body_excerpt.encode("utf-8")
    headers_truncated = len(selected_headers) > _MAX_PERSISTED_HEADERS or any(
        len(value) > _MAX_PERSISTED_HEADER_VALUE_CHARS
        for _, value in selected_headers[:_MAX_PERSISTED_HEADERS]
    )
    return (
        f"url={safe_http_evidence_url(observation.url)}\nmethod={observation.method}\n"
        f"status_code={observation.status_code}\nreason={observation.reason}\n"
        f"headers:\n{chr(10).join(safe_headers)}\n"
        f"headers_truncated={str(headers_truncated).lower()}\n"
        f"redirect_observed={str(redirect_was_observed(observation)).lower()}\n"
        f"body_excerpt_bytes={len(body)}\n"
        f"body_excerpt_sha256={sha256(body).hexdigest()}\n"
        f"body_truncated={str(body_truncated).lower()}"
    )
