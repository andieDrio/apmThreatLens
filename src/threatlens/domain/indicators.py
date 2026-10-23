"""Validated, passive indicators for a user's personal IOC collection."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from uuid import UUID, uuid4

_TYPES = {"ipv4", "ipv6", "domain", "md5", "sha1", "sha256"}
_HASH_LENGTHS = {"md5": 32, "sha1": 40, "sha256": 64}


@dataclass(frozen=True, slots=True)
class IOCIndicator:
    indicator_type: str
    value: str
    source: str
    confidence: float = 1.0
    tags: tuple[str, ...] = ()
    description: str | None = None
    id: UUID = field(default_factory=uuid4)


def normalize_ioc_indicator(
    *,
    indicator_type: str,
    value: str,
    source: str,
    confidence: float = 1.0,
    tags: tuple[str, ...] = (),
    description: str | None = None,
) -> IOCIndicator:
    """Canonicalize a passive IOC value without resolving or contacting it."""
    kind = indicator_type.strip().lower()
    if kind not in _TYPES:
        raise ValueError("unsupported indicator type")
    if not isinstance(value, str) or not value.strip() or len(value) > 512:
        raise ValueError("indicator value must be nonblank and at most 512 characters")
    raw_value = value.strip()
    if kind in {"ipv4", "ipv6"}:
        if "%" in raw_value:
            raise ValueError("scoped IP addresses are not supported")
        try:
            address = ipaddress.ip_address(raw_value)
        except ValueError as exc:
            raise ValueError("invalid IP address") from exc
        if (kind == "ipv4") != (address.version == 4):
            raise ValueError("IP address does not match indicator type")
        normalized = str(address)
    elif kind == "domain":
        if "://" in raw_value or "/" in raw_value or "@" in raw_value:
            raise ValueError("domain indicators must be hostnames only")
        try:
            normalized = raw_value.rstrip(".").encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise ValueError("invalid domain name") from exc
        labels = normalized.split(".")
        if (
            not normalized
            or len(normalized) > 253
            or len(labels) < 2
            or any(
                not label
                or len(label) > 63
                or label.startswith("-")
                or label.endswith("-")
                or not re.fullmatch(r"[a-z0-9-]+", label)
                for label in labels
            )
        ):
            raise ValueError("invalid domain name")
    else:
        if not re.fullmatch(rf"[0-9a-fA-F]{{{_HASH_LENGTHS[kind]}}}", raw_value):
            raise ValueError("invalid hash indicator")
        normalized = raw_value.lower()

    normalized_source = source.strip()
    if not normalized_source or len(normalized_source) > 128:
        raise ValueError("source must be nonblank and at most 128 characters")
    if (
        isinstance(confidence, bool)
        or not isinstance(confidence, (int, float))
        or not 0 <= confidence <= 1
    ):
        raise ValueError("confidence must be between 0 and 1")
    if len(tags) > 20:
        raise ValueError("at most 20 tags are allowed")
    normalized_tags = tuple(dict.fromkeys(tag.strip() for tag in tags))
    if any(not tag or len(tag) > 64 for tag in normalized_tags):
        raise ValueError("tags must be nonblank and at most 64 characters")
    normalized_description = description.strip() if description else None
    if normalized_description is not None and len(normalized_description) > 512:
        raise ValueError("description must be at most 512 characters")
    return IOCIndicator(
        indicator_type=kind,
        value=normalized,
        source=normalized_source,
        confidence=confidence,
        tags=normalized_tags,
        description=normalized_description or None,
    )
