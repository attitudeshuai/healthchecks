from __future__ import annotations

import hashlib
import time

from django.conf import settings
from django.core.signing import base64_hmac
from django.http import HttpResponse
from django.utils.http import http_date, parse_http_date_safe
from django.template.loader import render_to_string

from hc.lib.urls import absolute_reverse

WIDTHS = {
    "a": 7,
    "b": 7,
    "c": 6,
    "d": 7,
    "e": 6,
    "f": 4,
    "g": 7,
    "h": 7,
    "i": 3,
    "j": 3,
    "k": 7,
    "l": 3,
    "m": 10,
    "n": 7,
    "o": 7,
    "p": 7,
    "q": 7,
    "r": 4,
    "s": 6,
    "t": 5,
    "u": 7,
    "v": 7,
    "w": 9,
    "x": 6,
    "y": 7,
    "z": 7,
    "0": 7,
    "1": 6,
    "2": 7,
    "3": 7,
    "4": 7,
    "5": 7,
    "6": 7,
    "7": 7,
    "8": 7,
    "9": 7,
    "A": 8,
    "B": 7,
    "C": 8,
    "D": 8,
    "E": 7,
    "F": 6,
    "G": 9,
    "H": 8,
    "I": 3,
    "J": 4,
    "K": 7,
    "L": 6,
    "M": 10,
    "N": 8,
    "O": 9,
    "P": 6,
    "Q": 9,
    "R": 7,
    "S": 7,
    "T": 7,
    "U": 8,
    "V": 8,
    "W": 11,
    "X": 7,
    "Y": 7,
    "Z": 7,
    "-": 4,
    "_": 6,
}

COLORS = {"up": "#4c1", "late": "#fe7d37", "down": "#e05d44"}


def get_width(s: str) -> int:
    total = 0
    for c in s:
        total += WIDTHS.get(c, 7)
    return total


def get_badge_svg(tag: str, status: str) -> str:
    w1 = get_width(tag) + 10
    w2 = get_width(status) + 10
    ctx = {
        "width": str(w1 + w2),
        "tag_width": str(w1),
        "status_width": str(w2),
        "tag_center_x": str(w1 / 2),
        "status_center_x": str(w1 + w2 / 2),
        "tag": tag,
        "status": status,
        "color": COLORS[status],
    }

    return render_to_string("badge.svg", ctx)


def check_signature(badge_key: str, tag: str, sig: str) -> bool:
    ours = base64_hmac(str(badge_key), tag, settings.SECRET_KEY, algorithm="sha1")
    return ours[:8] == sig[:8]


def get_badge_url(
    badge_key: str, tag: str, fmt: str = "svg", with_late: bool = False
) -> str:
    sig = base64_hmac(str(badge_key), tag, settings.SECRET_KEY, algorithm="sha1")[:8]
    if not with_late:
        sig += "-2"

    if tag == "*":
        return absolute_reverse("hc-badge-all", args=[badge_key, sig, fmt])
    else:
        return absolute_reverse("hc-badge", args=[badge_key, sig, tag, fmt])


def _encode_etag_part(value: object) -> bytes:
    if isinstance(value, str):
        return value.encode()
    if isinstance(value, bool):
        return b"1" if value else b"0"
    if isinstance(value, int):
        return str(value).encode()
    if isinstance(value, (list, tuple)):
        return b"[" + b",".join(_encode_etag_part(v) for v in value) + b"]"
    return str(value).encode()


def make_etag(*parts: object) -> str:
    """Build an opaque, quoted ETag from the given representation parts.

    The parts must cover everything that affects the response body:
    the involved set of checks, their current statuses, and the
    aggregation parameters.
    """
    payload = b"\x1f".join(_encode_etag_part(p) for p in parts)
    digest = hashlib.sha1(payload).hexdigest()
    return f'"{digest}"'


def parse_if_none_match(header: str | None) -> list[str] | None:
    """Parse an If-None-Match header into a list of unquoted ETags.

    The wildcard "*" is returned as the string "*". Weak validators (W/"...")
    are accepted and compared with weak comparison semantics.

    Returns None if the header is absent or contains no syntactically valid
    tokens. Callers should then behave as if no validator was supplied.
    """
    if header is None:
        return None

    tokens: list[str] = []
    for raw in header.split(","):
        token = raw.strip()
        if token[:2].upper() == "W/":
            token = token[2:].strip()

        if token == "*":
            tokens.append("*")
        elif len(token) >= 2 and token[0] == '"' and token[-1] == '"':
            tokens.append(token[1:-1])

    return tokens or None


def etag_matches(header: str | None, etag: str) -> bool:
    """Check if If-None-Match contains the given (quoted) ETag or "*"."""
    tokens = parse_if_none_match(header)
    if not tokens:
        return False

    return "*" in tokens or etag[1:-1] in tokens


def fresh_if_modified_since(header: str | None, max_age: int) -> int | None:
    """Return the IMS timestamp if the cached copy is still fresh, else None.

    Honors an If-Modified-Since condition only while it is within max_age.
    Check statuses are time-derived (a check can enter grace/down without any
    database write), so an If-Modified-Since value older than max_age can no
    longer be trusted and the caller must produce a full response. Malformed
    headers return None and are treated as if no condition was supplied.
    """
    timestamp = parse_http_date_safe(header) if header is not None else None
    if timestamp is None:
        return None

    if time.time() - timestamp <= max_age:
        return timestamp

    return None


def apply_badge_cache_headers(
    response: HttpResponse,
    max_age: int,
    etag: str | None = None,
    last_modified: float | None = None,
) -> None:
    response["Cache-Control"] = f"max-age={max_age}"
    if etag:
        response["ETag"] = etag
    if last_modified is not None:
        response["Last-Modified"] = http_date(last_modified)
