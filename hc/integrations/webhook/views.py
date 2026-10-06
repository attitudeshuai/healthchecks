from __future__ import annotations

import json
from typing import Any
from uuid import UUID

from django.contrib.auth.decorators import login_required
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect, render

from hc.accounts.http import AuthenticatedHttpRequest
from hc.api.models import Channel
from hc.front.decorators import require_setting
from hc.front.views import _get_rw_project_for_user
from hc.integrations.webhook import forms
from hc.lib.credentials import get_keyring


@require_setting("WEBHOOKS_ENABLED")
def webhook_form(request: HttpRequest, channel: Channel) -> HttpResponse:
    adding = channel._state.adding
    encrypted = get_keyring().enabled
    configured: dict[str, bool] = {}
    if request.method == "POST":
        merge_existing = encrypted and not adding
        form = forms.WebhookForm(request.POST, merge_existing=merge_existing)
        if form.is_valid():
            channel.name = form.cleaned_data["name"]
            existing = None
            if merge_existing:
                existing = json.loads(channel.value)
                channel.audit_credential_access()
            channel.value = form.get_value(existing)
            channel.save()

            if adding:
                channel.assign_all_checks()

            return redirect("hc-channels", channel.project.code)
    elif adding:
        form = forms.WebhookForm()
    elif encrypted:
        # URLs and custom headers are not pre-filled. Reading the remaining
        # fields still requires decrypting the stored record, so audit access.
        doc = json.loads(channel.value)
        configured = {name: bool(doc.get(name)) for name in forms.WebhookForm.SENSITIVE_FIELDS}
        redacted: dict[str, Any] = dict(doc)
        redacted["url_down"] = ""
        redacted["url_up"] = ""
        redacted["headers_down"] = ""
        redacted["headers_up"] = ""
        redacted["name"] = channel.name
        form = forms.WebhookForm(redacted, merge_existing=True)
        channel.audit_credential_access()
    else:

        def flatten(d: dict[str, str]) -> str:
            return "\n".join("%s: %s" % pair for pair in d.items())

        doc = json.loads(channel.value)
        doc["headers_down"] = flatten(doc["headers_down"])
        doc["headers_up"] = flatten(doc["headers_up"])
        doc["name"] = channel.name
        form = forms.WebhookForm(doc)
        configured = {}

    ctx = {
        "page": "channels",
        "project": channel.project,
        "form": form,
        "is_new": adding,
        "credentials_encrypted": encrypted and not adding,
        "configured": configured,
    }
    return render(request, "webhook_form.html", ctx)


@require_setting("WEBHOOKS_ENABLED")
@login_required
def add(request: AuthenticatedHttpRequest, code: UUID) -> HttpResponse:
    project = _get_rw_project_for_user(request, code)
    channel = Channel(project=project, kind="webhook")
    return webhook_form(request, channel)
