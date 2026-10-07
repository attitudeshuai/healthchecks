from __future__ import annotations

from collections.abc import Callable

from django.http import HttpRequest, HttpResponse

from hc.api.ratelimit import RateLimitExceeded, rejected_response

MiddlewareFunc = Callable[[HttpRequest], HttpResponse]


class WriteRateLimitMiddleware:
    """Translate RateLimitExceeded into an explicit 429 rejection.

    The API write views catch the exception themselves (inside the CORS
    wrapper); this middleware covers the server-rendered write views, which
    raise it from the shared _get_rw_* access helpers. Inbound signals and
    read endpoints never raise, so they are unaffected.
    """

    def __init__(self, get_response: MiddlewareFunc) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        return self.get_response(request)

    def process_exception(
        self, request: HttpRequest, exception: Exception
    ) -> HttpResponse | None:
        if not isinstance(exception, RateLimitExceeded):
            return None

        is_api = request.path.startswith("/api/")
        return rejected_response(exception.state, json_shape=is_api)
