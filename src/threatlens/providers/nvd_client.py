"""Bounded HTTPS client for retrieving one CVE from the official NVD API."""

from __future__ import annotations

import json
import os
import re
import threading
import time
from collections.abc import Mapping

import httpx

from threatlens.providers.nvd_feed import parse_nvd_cve_response
from threatlens.providers.vulnerability_intelligence import VulnerabilityIntelligenceRecord

_NVD_CVE_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_CVE_ID_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_MAX_RESPONSE_BYTES = 2 * 1024 * 1024
_REQUEST_LOCK = threading.Lock()
_LAST_REQUEST_AT: dict[bool, float] = {}


def normalize_cve_id(cve_id: str) -> str:
    """Validate and normalize one CVE identifier before any network request."""
    normalized = cve_id.strip().upper()
    if not _CVE_ID_PATTERN.fullmatch(normalized):
        raise ValueError("invalid CVE identifier")
    return normalized


class NvdFeedError(RuntimeError):
    """Safe-to-report NVD transport or response error without request secrets."""


class NvdCveFeedClient:
    """Fetch a single, explicitly requested CVE with bounded HTTPS transport."""

    def __init__(
        self,
        api_key: str | None = None,
        *,
        timeout_seconds: float = 10.0,
        max_response_bytes: int = _MAX_RESPONSE_BYTES,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        if not 1.0 <= timeout_seconds <= 30.0:
            raise ValueError("timeout_seconds must be within 1..30")
        if not 1024 <= max_response_bytes <= _MAX_RESPONSE_BYTES:
            raise ValueError("max_response_bytes must be within 1024..2 MiB")
        if api_key is not None and (
            not api_key.strip()
            or len(api_key) > 512
            or "\r" in api_key
            or "\n" in api_key
        ):
            raise ValueError("NVD API key is invalid")
        self._api_key = api_key.strip() if api_key else None
        self._timeout_seconds = timeout_seconds
        self._max_response_bytes = max_response_bytes
        self._transport = transport

    @classmethod
    def from_environment(cls) -> NvdCveFeedClient:
        """Read the optional NVD key from the server process environment."""
        return cls(api_key=os.getenv("THREATLENS_NVD_API_KEY"))

    def fetch_cve(self, cve_id: str) -> tuple[VulnerabilityIntelligenceRecord, ...]:
        normalized_id = normalize_cve_id(cve_id)

        headers = {"apiKey": self._api_key} if self._api_key else {}
        try:
            # NVD recommends spacing requests; serialize clients in this process
            # so concurrent admin imports do not burst the public API.
            with _REQUEST_LOCK:
                has_api_key = self._api_key is not None
                interval = 1.0 if has_api_key else 6.0
                previous = _LAST_REQUEST_AT.get(has_api_key)
                if previous is not None:
                    time.sleep(max(0.0, previous + interval - time.monotonic()))
                _LAST_REQUEST_AT[has_api_key] = time.monotonic()
                with httpx.Client(
                    timeout=httpx.Timeout(self._timeout_seconds),
                    follow_redirects=False,
                    transport=self._transport,
                ) as client:
                    with client.stream(
                        "GET",
                        _NVD_CVE_ENDPOINT,
                        params={"cveId": normalized_id, "resultsPerPage": 1},
                        headers=headers,
                    ) as response:
                        if response.status_code != 200:
                            raise NvdFeedError(
                                f"NVD request failed with HTTP {response.status_code}"
                            )
                        body = bytearray()
                        for chunk in response.iter_bytes():
                            if len(body) + len(chunk) > self._max_response_bytes:
                                raise NvdFeedError(
                                    "NVD response exceeded the configured size limit"
                                )
                            body.extend(chunk)
        except httpx.TimeoutException as exc:
            raise NvdFeedError("NVD request timed out") from exc
        except httpx.HTTPError as exc:
            raise NvdFeedError("NVD HTTPS request failed") from exc

        try:
            payload = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise NvdFeedError("NVD returned invalid JSON") from exc
        if not isinstance(payload, Mapping):
            raise NvdFeedError("NVD response has an invalid structure")
        vulnerabilities = payload.get("vulnerabilities")
        if not isinstance(vulnerabilities, list) or len(vulnerabilities) > 1:
            raise NvdFeedError("NVD response has an invalid structure")
        if vulnerabilities:
            item = vulnerabilities[0]
            cve = item.get("cve") if isinstance(item, Mapping) else None
            if not isinstance(cve, Mapping) or cve.get("id") != normalized_id:
                raise NvdFeedError("NVD response did not match the requested CVE")
        try:
            records = parse_nvd_cve_response(payload)
        except ValueError as exc:
            raise NvdFeedError("NVD response has an invalid structure") from exc
        if any(record.cve != normalized_id for record in records):
            raise NvdFeedError("NVD response did not match the requested CVE")
        return records
