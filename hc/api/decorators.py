from __future__ import annotations

import json
from collections.abc import Callable
from functools import wraps
from typing import Any

from django.conf import settings
from django.http import HttpRequest, HttpResponse, JsonResponse

from hc.accounts.models import ApiKeyAudit, ApiKeyCredential, Project
from hc.lib.typealias import ViewFunc


class ApiRequest(HttpRequest):
    json: dict[Any, Any]
    project: Project
    readonly: bool
    v: int
    # "current" or "previous": which key generation authenticated this request.
    # Empty when API key governance is disabled.
    api_key_generation: str


def error(msg: str, status: int = 400) -> JsonResponse:
    return JsonResponse({"error": msg}, status=status)


def _get_api_version(request: HttpRequest) -> int:
    if request.path_info.startswith("/api/v3/"):
        return 3
    if request.path_info.startswith("/api/v2/"):
        return 2
    return 1


def authorize(f: ViewFunc) -> ViewFunc:
    @wraps(f)
    def wrapper(request: ApiRequest, *args: Any, **kwds: Any) -> HttpResponse:
        # For POST requests, we may need to look for the API key inside the
        # request body. Parse the body and put it in request.json
        # so views can avoid parsing it again.
        if request.method == "POST" and request.body:
            try:
                request.json = json.loads(request.body.decode())
            except ValueError:
                return error("could not parse request body")
            if not isinstance(request.json, dict):
                return error("json validation error: value is not an object")
        else:
            request.json = {}

        from_header = "X-Api-Key" in request.headers
        if from_header:
            api_key = request.headers["X-Api-Key"]
        elif "api_key" in request.json:
            api_key = str(request.json["api_key"])
        else:
            api_key = ""

        if len(api_key) != 32:
            return error("missing api key", 401)

        if settings.API_KEY_ROTATION_ENABLED:
            source = (
                ApiKeyAudit.Source.HEADER if from_header else ApiKeyAudit.Source.BODY
            )
            outcome = ApiKeyCredential.objects.authenticate(
                api_key, accept_rw=True, accept_ro=False, source=source
            )
            if not outcome.accepted or outcome.project is None:
                if outcome.expired:
                    return error("api key is expired", 401)
                return error("wrong api key", 401)

            request.project = outcome.project
            request.readonly = False
            request.api_key_generation = outcome.generation
        else:
            project = Project.objects.for_api_key(
                api_key, accept_rw=True, accept_ro=False
            )
            if project is None:
                return error("wrong api key", 401)

            request.project = project
            request.readonly = False
            request.api_key_generation = ""

        request.v = _get_api_version(request)
        return f(request, *args, **kwds)

    return wrapper


def authorize_read(f: ViewFunc) -> ViewFunc:
    @wraps(f)
    def wrapper(request: ApiRequest, *args: Any, **kwds: Any) -> HttpResponse:
        if "X-Api-Key" in request.headers:
            api_key = request.headers["X-Api-Key"]
        else:
            api_key = ""

        if len(api_key) != 32:
            return error("missing api key", 401)

        if settings.API_KEY_ROTATION_ENABLED:
            outcome = ApiKeyCredential.objects.authenticate(
                api_key,
                accept_rw=True,
                accept_ro=True,
                source=ApiKeyAudit.Source.HEADER,
            )
            if not outcome.accepted or outcome.project is None:
                if outcome.expired:
                    return error("api key is expired", 401)
                return error("wrong api key", 401)

            request.project = outcome.project
            request.readonly = outcome.readonly
            request.api_key_generation = outcome.generation
        else:
            project = Project.objects.for_api_key(
                api_key, accept_rw=True, accept_ro=True
            )
            if project is None:
                return error("wrong api key", 401)

            request.project = project
            request.readonly = (
                api_key.startswith("hcr_")
                or api_key == request.project.api_key_readonly
            )
            request.api_key_generation = ""

        request.v = _get_api_version(request)
        return f(request, *args, **kwds)

    return wrapper


def cors(*methods: str) -> Callable[[ViewFunc], ViewFunc]:
    methods_set = set(methods)
    methods_set.add("OPTIONS")
    methods_str = ", ".join(methods_set)

    def decorator(f: ViewFunc) -> ViewFunc:
        @wraps(f)
        def wrapper(request: HttpRequest, *args: Any, **kwds: Any) -> HttpResponse:
            if request.method == "OPTIONS":
                # Handle OPTIONS here
                response = HttpResponse(status=204)
            elif request.method in methods:
                response = f(request, *args, **kwds)
            else:
                response = HttpResponse(status=405)

            response["Access-Control-Allow-Origin"] = "*"
            response["Access-Control-Allow-Headers"] = "X-Api-Key"
            response["Access-Control-Allow-Methods"] = methods_str
            response["Access-Control-Max-Age"] = "600"
            return response

        return wrapper

    return decorator
