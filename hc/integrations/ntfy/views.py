from __future__ import annotations

from uuid import UUID

from django.contrib.auth.decorators import login_required
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect, render

from hc.accounts.http import AuthenticatedHttpRequest
from hc.api.models import Channel
from hc.front.views import _get_rw_project_for_user
from hc.integrations.ntfy.forms import NtfyForm
from hc.lib.credentials import get_keyring


def ntfy_form(request: HttpRequest, channel: Channel) -> HttpResponse:
    adding = channel._state.adding
    encrypted = get_keyring().enabled
    if request.method == "POST":
        form = NtfyForm(request.POST)
        if form.is_valid():
            existing_token = None
            if encrypted and not adding:
                existing_token = channel.ntfy.token
                channel.audit_credential_access()

            channel.value = form.get_value(existing_token)
            channel.save()

            if adding:
                channel.assign_all_checks()
            return redirect("hc-channels", channel.project.code)
    elif adding:
        form = NtfyForm()
    else:
        if encrypted:
            # Do not pre-fill the stored token. Reading the other fields still
            # requires decrypting the record, so audit the credential access.
            form = NtfyForm(
                {
                    "topic": channel.ntfy.topic,
                    "url": channel.ntfy.url,
                    "priority": channel.ntfy.priority,
                    "priority_up": channel.ntfy.priority_up,
                }
            )
            channel.audit_credential_access()
        else:
            form = NtfyForm(
                {
                    "topic": channel.ntfy.topic,
                    "url": channel.ntfy.url,
                    "priority": channel.ntfy.priority,
                    "priority_up": channel.ntfy.priority_up,
                    "token": channel.ntfy.token,
                }
            )

    ctx = {
        "page": "channels",
        "project": channel.project,
        "form": form,
        "is_new": adding,
        "credentials_encrypted": encrypted and not adding,
        "token_configured": bool(not adding and channel.stored_envelope()),
    }
    return render(request, "ntfy_form.html", ctx)


@login_required
def add(request: AuthenticatedHttpRequest, code: UUID) -> HttpResponse:
    project = _get_rw_project_for_user(request, code)
    channel = Channel(project=project, kind="ntfy")
    return ntfy_form(request, channel)
