from __future__ import annotations

from uuid import UUID

from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.shortcuts import redirect, render

from hc.accounts.http import AuthenticatedHttpRequest
from hc.api.models import Channel
from hc.front.views import _get_rw_project_for_user
from hc.integrations.gotify.forms import GotifyForm
from hc.lib.credentials import get_keyring


@login_required
def gotify_form(request: AuthenticatedHttpRequest, channel: Channel) -> HttpResponse:
    adding = channel._state.adding
    encrypted = get_keyring().enabled
    if request.method == "POST":
        form = GotifyForm(request.POST)
        # The token is not shown when editing an encrypted channel, so it is
        # only required when adding a new channel.
        if encrypted and not adding:
            form.fields["token"].required = False
        if form.is_valid():
            existing_token = None
            if encrypted and not adding:
                existing_token = channel.gotify.token
                channel.audit_credential_access()

            channel.value = form.get_value(existing_token)
            channel.save()

            if adding:
                channel.assign_all_checks()
            return redirect("hc-channels", channel.project.code)
    elif adding:
        form = GotifyForm()
    else:
        # When editing an already configured integration, if priority is not set
        # then use normal priority as the default.
        def setdefault(prio: int | None) -> int:
            if prio is None:
                return 5
            return prio

        if encrypted:
            # Do not pre-fill the stored token. Reading the other fields still
            # requires decrypting the record, so audit the credential access.
            initial = {
                "url": channel.gotify.url,
                "priority": setdefault(channel.gotify.priority),
                "priority_up": setdefault(channel.gotify.priority_up),
            }
            form = GotifyForm(initial)
            form.fields["token"].required = False
            channel.audit_credential_access()
        else:
            form = GotifyForm(
                {
                    "token": channel.gotify.token,
                    "url": channel.gotify.url,
                    "priority": setdefault(channel.gotify.priority),
                    "priority_up": setdefault(channel.gotify.priority_up),
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
    return render(request, "gotify_form.html", ctx)


@login_required
def add(request: AuthenticatedHttpRequest, code: UUID) -> HttpResponse:
    project = _get_rw_project_for_user(request, code)
    channel = Channel(project=project, kind="gotify")
    return gotify_form(request, channel)
