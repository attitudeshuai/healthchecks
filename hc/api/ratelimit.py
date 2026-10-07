"""Configurable fixed-window rate limiting for authenticated write requests.

Configuration comes from either the admin-managed RateLimitConfig singleton
(which takes precedence) or the WRITE_RATE_LIMIT Django setting /
environment variable. Limiting is opt-in: when neither source is
configured, write endpoints behave exactly as before.

The limiter counts requests in fixed, epoch-aligned time windows and can
bucket them per project or per account (project owner). State lives only in
the database (RateLimitCounter rows); the check-and-increment sequence runs
inside one transaction while holding a row lock, so concurrent requests
can never push the count past the configured limit.

Read requests and inbound signals never call enforce_write_rate_limit(),
so they are unaffected.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.db import IntegrityError, transaction
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.utils.timezone import now

from hc.api.models import RateLimitConfig, RateLimitCounter

if TYPE_CHECKING:
    from hc.accounts.models import Project

# Raw configuration tuple: (scope, limit, window_seconds)
RawConfig = tuple[str, int, int]


class InvalidRateLimitConfig(Exception):
    """The active write-rate-limit configuration is invalid.

    Raised on write attempts when a configured value cannot be applied
    (negative limit, zero/negative window, unknown scope). The stored
    configuration itself is left untouched.
    """


class RateLimitExceeded(Exception):
    """Raised when a write request does not fit into the current window."""

    def __init__(self, state: WindowState):
        self.state = state
        super().__init__(state.message())


@dataclass(frozen=True)
class WindowState:
    scope: str
    limit: int
    window_secs: int
    used: int
    window_start: datetime
    window_end: datetime

    @property
    def remaining(self) -> int:
        return max(0, self.limit - self.used)

    @property
    def retry_after(self) -> int:
        seconds = (self.window_end - now()).total_seconds()
        # Never tell the client to retry immediately when rejected:
        return max(1, math.ceil(seconds))

    def message(self) -> str:
        return (
            f"write rate limit exceeded: {self.limit} write requests per "
            f"{self.window_secs} seconds allowed for this {self.scope}, "
            f"retry in {self.retry_after} seconds"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "scope": self.scope,
            "limit": self.limit,
            "window_secs": self.window_secs,
            "used": self.used,
            "remaining": self.remaining,
            "window_start": self.window_start.replace(microsecond=0).isoformat(),
            "window_end": self.window_end.replace(microsecond=0).isoformat(),
            "retry_after": self.retry_after,
        }

    def headers(self) -> dict[str, str]:
        return {
            "X-RateLimit-Limit": str(self.limit),
            "X-RateLimit-Remaining": str(self.remaining),
            "X-RateLimit-Reset": str(int(self.window_end.timestamp())),
        }


def validate_config(raw: Any, *, source: str) -> RawConfig:
    """Validate a raw (scope, limit, window_secs) configuration tuple.

    Raises InvalidRateLimitConfig / ImproperlyConfigured with an explicit
    message on negative limits, non-positive windows or unknown scopes.
    """

    error_cls = (
        ImproperlyConfigured if source == "settings" else InvalidRateLimitConfig
    )
    try:
        scope, limit, window_secs = raw
    except (TypeError, ValueError) as e:
        raise error_cls(
            f"WRITE_RATE_LIMIT must be a (scope, limit, window_secs) tuple: {raw!r}"
        ) from e

    if scope not in RateLimitConfig.Scope.values:
        raise error_cls(
            f"WRITE_RATE_LIMIT scope must be 'project' or 'account', got {scope!r}"
        )
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 0:
        raise error_cls(
            f"WRITE_RATE_LIMIT limit must be a non-negative integer, got {limit!r}"
        )
    if (
        not isinstance(window_secs, int)
        or isinstance(window_secs, bool)
        or window_secs < 1
    ):
        raise error_cls(
            "WRITE_RATE_LIMIT window_secs must be a positive integer, "
            f"got {window_secs!r}"
        )

    return scope, int(limit), int(window_secs)


def _settings_config() -> RawConfig | None:
    raw = getattr(settings, "WRITE_RATE_LIMIT", None)
    if raw is None:
        return None
    return validate_config(raw, source="settings")


def get_active_config() -> RawConfig | None:
    """Resolve the effective (scope, limit, window_secs) configuration.

    The admin-managed singleton wins when it is fully configured; otherwise
    fall back to the configuration-file setting. Returns None when limiting
    is disabled.
    """

    row = RateLimitConfig.load()
    if row is not None and row.is_configured:
        # Rows saved through the admin are validated on save, but validate
        # again in case a row was written by other means:
        return validate_config(
            (row.scope, row.limit, row.window_secs), source="database"
        )

    return _settings_config()


def _bucket(
    project: Project, scope: str, window_secs: int, frozen_now: datetime
) -> tuple[str, str, datetime, datetime]:
    """Return (prefix, value, window_start, window_end) for the current window."""

    scope_id = project.owner_id if scope == RateLimitConfig.Scope.ACCOUNT else project.id
    letter = "a" if scope == RateLimitConfig.Scope.ACCOUNT else "p"
    prefix = f"write-{letter}-{scope_id}-"

    idx = int(frozen_now.timestamp()) // window_secs
    window_start = datetime.fromtimestamp(idx * window_secs, tz=timezone.utc)
    window_end = window_start + timedelta(seconds=window_secs)
    return prefix, prefix + str(idx), window_start, window_end


def _make_state(
    project: Project,
    cfg: RawConfig,
    used: int,
    frozen_now: datetime,
) -> WindowState:
    scope, limit, window_secs = cfg
    _, _, window_start, window_end = _bucket(project, scope, window_secs, frozen_now)
    return WindowState(
        scope=scope,
        limit=limit,
        window_secs=window_secs,
        used=used,
        window_start=window_start,
        window_end=window_end,
    )


def current_window(project: Project, *, consume: bool) -> WindowState | None:
    """Return the current window state for a project.

    When consume=True, atomically reserves one write slot and raises
    RateLimitExceeded if the window is full. When consume=False, reports the
    state without touching counters (used by the read-only status endpoint).
    Returns None when write rate limiting is not configured.
    """

    cfg = get_active_config()
    if cfg is None:
        return None

    scope, limit, window_secs = cfg
    frozen_now = now()
    prefix, value, window_start, _window_end = _bucket(
        project, scope, window_secs, frozen_now
    )

    if not consume:
        counter = RateLimitCounter.objects.filter(value=value).first()
        used = counter.count if counter else 0
        return _make_state(project, cfg, used, frozen_now)

    with transaction.atomic():
        try:
            # Nested atomic so a unique-violation from a concurrent insert
            # rolls back just to the savepoint and we can re-read the row:
            with transaction.atomic():
                counter, created = RateLimitCounter.objects.get_or_create(
                    value=value,
                    defaults={"count": 0, "window_start": window_start},
                )
        except IntegrityError:
            created = False
            counter = RateLimitCounter.objects.select_for_update().get(value=value)

        if not created:
            # Re-read under a lock so concurrent increments serialize:
            counter = RateLimitCounter.objects.select_for_update().get(value=value)

        used = counter.count
        if used >= limit:
            raise RateLimitExceeded(_make_state(project, cfg, used, frozen_now))

        counter.count = used + 1
        counter.save(update_fields=["count"])

    if created:
        # First write in a fresh window: drop this bucket's previous windows.
        # Runs once per bucket per window, outside the locked transaction.
        RateLimitCounter.objects.filter(
            value__startswith=prefix, window_start__lt=window_start
        ).delete()

    return _make_state(project, cfg, used + 1, frozen_now)


def enforce_write_rate_limit(
    project: Project, request: HttpRequest | None = None
) -> WindowState | None:
    """Consume one write slot. Called from authenticated write endpoints.

    Raises RateLimitExceeded (with retry-after information) when the current
    window is exhausted. Returns None when limiting is not configured, so
    unconfigured deployments behave exactly as before.

    Some requests pass through several project/check access helpers (for
    example the project-transfer view resolves both the check and the target
    project); pass the request so such a request consumes at most one slot.
    """

    if request is not None:
        cached = getattr(request, "_write_rate_limit_state", None)
        if isinstance(cached, WindowState):
            return cached

    state = current_window(project, consume=True)

    if request is not None and state is not None:
        setattr(request, "_write_rate_limit_state", state)

    return state


def rejected_response(state: WindowState, *, json_shape: bool) -> HttpResponse:
    """Build the explicit rejection response for an exhausted window."""

    if json_shape:
        response: HttpResponse = JsonResponse({"error": state.message()}, status=429)
    else:
        response = HttpResponse(state.message(), status=429, content_type="text/plain")
    response["Retry-After"] = str(state.retry_after)
    for key, value in state.headers().items():
        response[key] = value
    return response


def annotate_response(response: HttpResponse, state: WindowState) -> HttpResponse:
    """Attach rate-limit headers describing the current window."""

    for key, value in state.headers().items():
        response[key] = value
    return response
