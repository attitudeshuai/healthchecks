from __future__ import annotations

import hmac
import random
import uuid
from dataclasses import dataclass
from datetime import date, datetime
from datetime import timedelta as td
from secrets import token_urlsafe
from typing import TYPE_CHECKING, Any
from urllib.parse import quote, urlencode
from zoneinfo import ZoneInfo

from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password
from django.contrib.auth.models import User
from django.core.signing import BadSignature, TimestampSigner
from django.db import models, transaction
from django.db.models import Q, QuerySet
from django.db.models.functions import Lower
from django.template.loader import render_to_string
from django.urls import reverse
from django.utils.timezone import now

from hc.lib import emails
from hc.lib.date import day_boundaries, month_boundaries, week_boundaries
from hc.lib.signing import sign_bounce_id
from hc.lib.urls import absolute_reverse

if TYPE_CHECKING:
    # Importing Check at runtime would cause a circular import, so only import it
    # during type checking
    from hc.api.models import Check

    CheckQuerySet = QuerySet[Check]


NO_NAG = td()
NAG_PERIODS = (
    (NO_NAG, "Disabled"),
    (td(hours=1), "Hourly"),
    (td(days=1), "Daily"),
)

REPORT_CHOICES = (
    ("off", "Off"),
    ("daily", "Daily"),
    ("weekly", "Weekly"),
    ("monthly", "Monthly"),
)
# How long an account can be over limits before it is scheduled for deletion
OVER_LIMIT_GRACE = td(days=31)
# When scheduling for deletion, how many days in the future to schedule
DELETION_GRACE = td(days=31)


class ApiKeyError(Exception):
    """Base class for API key governance errors."""


class RotationInProgressError(ApiKeyError):
    """Raised when a rotation is started while a rotation window is open.

    A slot can hold at most the current and the previous key, so starting
    a second rotation before the window closes would create an unreconcilable
    state with three live keys.
    """


class NoCurrentKeyError(ApiKeyError):
    """Raised when an operation requires a current key but the slot is empty."""


def governance_seconds(setting_name: str) -> int:
    """Return a governance duration setting as a positive int.

    hc.api.apps.api_key_governance_check guarantees (at startup, when
    governance is enabled) that these settings are positive integers.
    """
    value = getattr(settings, setting_name)
    assert isinstance(value, int) and value > 0
    return value


def month(dt: datetime) -> date:
    """For a given datetime, return the matching first-day-of-month date."""
    return dt.date().replace(day=1)


class ProfileManager(models.Manager["Profile"]):
    def for_user(self, user: User) -> Profile:
        try:
            return user.profile
        except Profile.DoesNotExist:
            profile = Profile(user=user)
            if not settings.USE_PAYMENTS:
                # If not using payments, set high limits
                profile.check_limit = 10000
                profile.sms_limit = 10000
                profile.call_limit = 10000

            profile.save()
            return profile


class Profile(models.Model):
    user = models.OneToOneField(User, models.CASCADE)
    next_report_date = models.DateTimeField(null=True, blank=True)
    reports = models.CharField(max_length=10, default="monthly", choices=REPORT_CHOICES)
    nag_period = models.DurationField(default=NO_NAG, choices=NAG_PERIODS)
    next_nag_date = models.DateTimeField(null=True, blank=True)
    ping_log_limit = models.IntegerField(default=100)
    check_limit = models.IntegerField(default=20)
    token = models.CharField(max_length=128, blank=True)

    last_sms_date = models.DateTimeField(null=True, blank=True)
    sms_limit = models.IntegerField(default=0)
    sms_sent = models.IntegerField(default=0)

    last_call_date = models.DateTimeField(null=True, blank=True)
    call_limit = models.IntegerField(default=0)
    calls_sent = models.IntegerField(default=0)

    sort = models.CharField(max_length=20, default="created")
    # The date when "Inactive Account Notification" is sent
    deletion_notice_date = models.DateTimeField(null=True, blank=True)
    # Set manually by admin, causes an orange banner in web UI
    deletion_scheduled_date = models.DateTimeField(null=True, blank=True)
    # If the account is over its check limit, the date when it went over the limit
    over_limit_date = models.DateTimeField(null=True, blank=True)
    last_active_date = models.DateTimeField(null=True, blank=True)
    tz = models.CharField(max_length=36, default="UTC")
    theme = models.CharField(max_length=10, null=True, blank=True)

    totp = models.CharField(max_length=32, null=True, blank=True)
    totp_created = models.DateTimeField(null=True, blank=True)

    objects = ProfileManager()

    def __str__(self) -> str:
        return f"Profile for {self.user.email}"

    def notifications_url(self) -> str:
        return absolute_reverse("hc-notifications")

    def reports_unsub_url(self) -> str:
        signer = TimestampSigner(salt="reports")
        signed_username = signer.sign(self.user.username)
        return absolute_reverse("hc-unsubscribe-reports", args=[signed_username])

    def prepare_token(self) -> str:
        token = token_urlsafe(24)
        # Store a hashed transformation of the login token
        self.token = make_password(token)
        self.save()
        # Sign the token so we can check its age later
        return TimestampSigner().sign(token)

    def check_token(self, token: str) -> bool:
        try:
            token = TimestampSigner().unsign(token, max_age=3600)
        except BadSignature:
            return False

        return check_password(token, self.token)

    def send_instant_login_link(
        self, membership: Member | None = None, redirect_url: str | None = None
    ) -> None:
        token = self.prepare_token()
        query = {"next": redirect_url} if redirect_url else None
        url = absolute_reverse(
            "hc-check-token", args=[self.user.username, token], query=query
        )

        ctx = {
            "button_text": "Log In",
            "button_url": url,
            "membership": membership,
        }
        emails.login(self.user.email, ctx)

    def send_change_email_link(self, new_email: str) -> None:
        payload = {
            "u": self.user.username,
            "t": self.prepare_token(),
            "e": new_email,
        }
        signed_payload = TimestampSigner().sign_object(payload)
        url = absolute_reverse("hc-change-email-verify", args=[signed_payload])

        ctx = {
            "button_text": "Log In",
            "button_url": url,
        }
        emails.login(new_email, ctx)

    def send_transfer_request(self, project: Project) -> None:
        token = self.prepare_token()
        settings_path = reverse("hc-project-settings", args=[project.code])
        url = absolute_reverse(
            "hc-check-token",
            args=[self.user.username, token],
            query={"next": settings_path},
        )

        ctx = {
            "button_text": "Project Settings",
            "button_url": url,
            "project": project,
        }
        emails.transfer_request(self.user.email, ctx)

    def project_ids(self) -> QuerySet[Project, tuple[int]]:
        """Return a queryset returning IDs of all projects we have access to."""
        # Construct a UNION of two simple queries. This could be alternatively
        # be done in a single query and filtering by Q(is_owner) | Q(is_member).
        # But the single query approach has significantly worse performance
        # on PostgreSQL.
        owned_ids = Project.objects.filter(owner_id=self.user_id).values_list("id")
        joined_ids = Member.objects.filter(user_id=self.user_id).values_list(
            "project_id"
        )
        return owned_ids.union(joined_ids)

    def projects(self) -> QuerySet[Project]:
        """Return a queryset of all projects we have access to."""
        return Project.objects.filter(id__in=self.project_ids()).order_by(Lower("name"))

    def checks_from_all_projects(self) -> CheckQuerySet:
        """Return a queryset of checks from projects we have access to."""

        from hc.api.models import Check

        return Check.objects.filter(project__in=self.project_ids())

    def send_report(self, nag: bool = False) -> bool:
        q = self.checks_from_all_projects()

        # Has there been a ping in last 6 months?
        result = q.aggregate(models.Max("last_ping"))
        last_ping = result["last_ping__max"]

        six_months_ago = now() - td(days=180)
        if last_ping is None or last_ping < six_months_ago:
            return False

        # Sort checks by project. Need this because will group by project in template.
        # Sort primarily by project name, but projects can have duplicate names
        # so sort by project id also.
        # Checks in each project will be sorted by check name in the template,
        # after grouping.
        q = q.select_related("project").order_by("project__name", "project_id")
        # list() executes the query, to avoid DB access while rendering the template.
        checks = list(q)

        unsub_url = self.reports_unsub_url()
        headers = {
            "X-Bounce-ID": sign_bounce_id(f"r.{self.user.username}"),
            "List-Unsubscribe": f"<{unsub_url}>",
            "List-Unsubscribe-Post": "List-Unsubscribe=One-Click",
        }
        ctx: dict[str, Any] = {
            "unsub_link": unsub_url,
            "notifications_url": self.notifications_url(),
            "tz": self.tz,
        }

        if not nag:
            # For monthly/weekly/daily reports, calculate the downtimes,
            # throw away the current period, keep two previous periods
            if self.reports == "monthly":
                boundaries = month_boundaries(3, self.tz)
            elif self.reports == "weekly":
                boundaries = week_boundaries(3, self.tz)
            elif self.reports == "daily":
                boundaries = day_boundaries(3, self.tz)
            else:
                assert 0, f"Unexpected Profile.reports value: {self.reports}"

            ctx["summary_nchecks"] = 0
            ctx["summary_ntimes"] = 0
            for check in checks:
                downtimes = check.downtimes_by_boundary(boundaries, self.tz)
                # downtimes_by_boundary returns records in descending order,
                # but the template will need them in ascending order:
                downtimes.reverse()
                check.past_downtimes = downtimes[:-1]
                if count := check.past_downtimes[-1].count:
                    ctx["summary_nchecks"] += 1
                    ctx["summary_ntimes"] += count

            # boundaries are in descending order, but the template
            # will need them in ascending order:
            boundaries.reverse()
            ctx["checks"] = checks
            ctx["boundaries"] = boundaries[:-1]
            ctx["report_period"] = self.reports

            # Prepare the "In January" / "Last week (...)" / "Yesterday (...)" bit:
            when_ctx = {
                "boundary": ctx["boundaries"][-1],
                "report_period": self.reports,
                "tz": self.tz,
            }
            ctx["when"] = render_to_string("emails/report-when.html", when_ctx).strip()

            emails.report(self.user.email, ctx, headers)

        if nag:
            # For nags, only show checks that are currently down
            checks = [c for c in checks if c.get_status() == "down"]
            if not checks:
                return False
            ctx["checks"] = checks
            ctx["num_down"] = len(checks)
            ctx["nag_period"] = self.nag_period.total_seconds()
            emails.nag(self.user.email, ctx, headers)

        return True

    def sms_sent_this_month(self) -> int:
        # IF last_sms_date was never set, we have not sent any messages yet.
        if not self.last_sms_date:
            return 0

        # If last sent date is not from this month, we've sent 0 this month.
        if month(now()) > month(self.last_sms_date):
            return 0

        return self.sms_sent

    def authorize_sms(self) -> bool:
        """If monthly limit not exceeded, increase counter and return True"""

        sent_this_month = self.sms_sent_this_month()
        if sent_this_month >= self.sms_limit:
            return False

        self.sms_sent = sent_this_month + 1
        self.last_sms_date = now()
        self.save()
        return True

    def calls_sent_this_month(self) -> int:
        # IF last_call_date was never set, we have not made any phone calls yet.
        if not self.last_call_date:
            return 0

        # If last sent date is not from this month, we've made 0 calls this month.
        if month(now()) > month(self.last_call_date):
            return 0

        return self.calls_sent

    def authorize_call(self) -> bool:
        """If monthly limit not exceeded, increase counter and return True"""

        sent_this_month = self.calls_sent_this_month()
        if sent_this_month >= self.call_limit:
            return False

        self.calls_sent = sent_this_month + 1
        self.last_call_date = now()
        self.save()
        return True

    def num_checks_used(self) -> int:
        from hc.api.models import Check

        return Check.objects.filter(project__owner_id=self.user_id).count()

    def num_checks_available(self) -> int:
        return self.check_limit - self.num_checks_used()

    def can_accept(self, project: Project) -> bool:
        return project.check_set.count() <= self.num_checks_available()

    def update_next_nag_date(self) -> None:
        any_down = self.checks_from_all_projects().filter(status="down").exists()
        if any_down and self.next_nag_date is None and self.nag_period:
            self.next_nag_date = now() + self.nag_period
            self.save(update_fields=["next_nag_date"])
        elif not any_down and self.next_nag_date:
            self.next_nag_date = None
            self.save(update_fields=["next_nag_date"])

    def choose_next_report_date(self) -> datetime | None:
        """Calculate the target date for the next monthly/weekly report.

        Monthly reports should get sent on 1st of each month, between
        9AM and 11AM in user's timezone.

        Weekly reports should get sent on Mondays, between
        9AM and 11AM in user's timezone.

        """

        if self.reports == "off":
            return None

        dt = now().astimezone(ZoneInfo(self.tz))
        dt = dt.replace(hour=9, minute=0) + td(minutes=random.randrange(0, 120))

        while True:
            dt += td(days=1)
            if self.reports == "daily":
                return dt
            if self.reports == "monthly" and dt.day == 1:
                return dt
            if self.reports == "weekly" and dt.weekday() == 0:
                return dt

    def is_past_over_limit_grace(self) -> bool:
        """Return True if this profile is over limits for 31 or more days."""
        if not self.over_limit_date:
            return False

        return now() > self.over_limit_date + OVER_LIMIT_GRACE

    def schedule_for_deletion(self) -> None:
        self.deletion_scheduled_date = now() + DELETION_GRACE
        self.save()


class ProjectManager(models.Manager["Project"]):
    def for_api_key(
        self, api_key: str, accept_rw: bool, accept_ro: bool
    ) -> Project | None:
        """Look up project by API key.

        This handles both the old plain text API keys, and the new hashed API keys.
        For the hashed API keys, it looks up project by the first 8 characters of the
        random part of the key, then calls Project.compare_api_key().
        """

        # Hashed keys
        if accept_rw and api_key.startswith("hcw_"):
            secret8 = api_key[4:12]
            for project in Project.objects.filter(api_key__startswith=secret8):
                if project.compare_api_key(api_key):
                    return project

        if accept_ro and api_key.startswith("hcr_"):
            secret8 = api_key[4:12]
            for project in Project.objects.filter(api_key_readonly__startswith=secret8):
                if project.compare_api_key(api_key):
                    return project

        # Plain text keys
        if accept_rw and accept_ro:
            write_key_match = Q(api_key=api_key)
            read_key_match = Q(api_key_readonly=api_key)
            try:
                return Project.objects.get(write_key_match | read_key_match)
            except Project.DoesNotExist:
                pass
        elif accept_rw:
            try:
                return Project.objects.get(api_key=api_key)
            except Project.DoesNotExist:
                pass
        elif accept_ro:
            try:
                return Project.objects.get(api_key_readonly=api_key)
            except Project.DoesNotExist:
                pass

        return None


class Project(models.Model):
    code = models.UUIDField(default=uuid.uuid4, unique=True)
    name = models.CharField(max_length=200, blank=True)
    owner = models.ForeignKey(User, models.CASCADE)
    api_key = models.CharField(max_length=128, blank=True, db_index=True)
    api_key_readonly = models.CharField(max_length=128, blank=True, db_index=True)
    badge_key = models.CharField(max_length=150, unique=True)
    ping_key = models.CharField(max_length=128, blank=True, null=True, unique=True)
    show_slugs = models.BooleanField(default=False)

    objects = ProjectManager()
    # used in hc.front.views to cache the aggregate status of all checks in the project
    overall_status: str
    any_started: bool

    def __str__(self) -> str:
        return self.name or self.owner.email

    @property
    def owner_profile(self) -> Profile:
        return Profile.objects.for_user(self.owner)

    def num_checks_available(self) -> int:
        return self.owner_profile.num_checks_available()

    def invite_suggestions(self) -> QuerySet[User]:
        q = User.objects.filter(memberships__project__owner_id=self.owner_id)
        q = q.exclude(memberships__project=self)
        return q.distinct().order_by("email")

    def invite(self, user: User, role: str) -> bool:
        if Member.objects.filter(user=user, project=self).exists():
            return False

        if self.owner_id == user.id:
            return False

        m = Member.objects.create(user=user, project=self, role=role)
        checks_url = reverse("hc-checks", args=[self.code])

        if settings.MAILERS:
            profile = Profile.objects.for_user(user)
            profile.send_instant_login_link(membership=m, redirect_url=checks_url)
        return True

    def update_next_nag_dates(self) -> None:
        """Update next_nag_date on profiles of all members of this project."""

        # Use an UNION of two simple queries to look up project's user ids.
        # On PostgreSQL this is much faster than using JOIN.
        owner_id = User.objects.filter(id=self.owner_id).values_list("id")
        member_ids = Member.objects.filter(project=self).values_list("user_id")
        user_ids = owner_id.union(member_ids)

        q = Profile.objects.filter(user_id__in=user_ids).exclude(nag_period=NO_NAG)
        for profile in q:
            profile.update_next_nag_date()

    def get_n_down(self) -> int:
        result = 0
        for check in self.check_set.all():
            if check.get_status() == "down":
                result += 1

        return result

    def have_channel_issues(self) -> bool:
        errors = list(self.channel_set.values_list("last_error", flat=True))

        # It's a problem if a project has no integrations at all
        if len(errors) == 0:
            return True

        # It's a problem if any integration has a logged error
        return any(errors)

    def transfer_request(self) -> Member | None:
        return self.member_set.filter(transfer_request_date__isnull=False).first()

    def dashboard_url(self) -> str | None:
        if not self.api_key_readonly:
            return None

        frag = urlencode({self.api_key_readonly: str(self)}, quote_via=quote)
        return reverse("hc-dashboard", fragment=frag)

    def checks_url(self) -> str:
        return absolute_reverse("hc-checks", args=[self.code])

    def auth_metrics_url(self) -> str:
        return absolute_reverse("hc-auth-metrics", args=[self.code])

    def get_absolute_url(self) -> str:
        return reverse("hc-checks", args=[self.code])

    def _make_api_key(self, prefix: str) -> tuple[str, str]:
        """Generate an API key with specified prefix, return (key, key_hash) tuple.

        * `key` is what will be presented to the user,
        * `key_hash` will be stored in the database.

        `key_hash` consists of two parts:
        * first 8 characters: the first 8 characters of plain text key
          (for efficiently looking up project in the database by its API key)
        * next 64 characters: HMAC(SECRET_KEY, key)
        """
        while True:
            secret = token_urlsafe(21)
            if "-" not in secret and "_" not in secret:
                break

        key = f"{prefix}{secret}"
        digest = hmac.digest(settings.SECRET_KEY.encode(), key.encode(), "sha256")
        return key, secret[:8] + "." + digest.hex()

    def set_api_key(self) -> str:
        key, key_hash = self._make_api_key("hcw_")
        self.api_key = key_hash
        return key

    def set_api_key_readonly(self) -> str:
        key, key_hash = self._make_api_key("hcr_")
        self.api_key_readonly = key_hash
        return key

    def set_ping_key(self) -> str:
        # The ping key will be:
        # - 22 characters long, consisting of [a-z0-9]
        # - no "_" or "-" characters for aesthetic reasons
        # - no uppercase characters to avoid case-sensitivity issues
        #   in email addresses.
        # The ping key will have ~113 bits of entropy.
        while True:
            self.ping_key = token_urlsafe(16).lower()
            if "_" not in self.ping_key and "-" not in self.ping_key:
                break
        return self.ping_key

    def compare_api_key(self, key: str) -> bool:
        if key.startswith("hcr_"):
            expected = self.api_key_readonly
        else:
            expected = self.api_key

        # Only calculate and compare digest if db key length is 8 + 64 = 72
        if "." not in expected:
            return False
        _, key_hash = expected.split(".", maxsplit=1)

        digest = hmac.digest(settings.SECRET_KEY.encode(), key.encode(), "sha256")
        return hmac.compare_digest(digest.hex(), key_hash)

    def team_emails(self) -> list[str]:
        q = User.objects.filter(memberships__project=self).order_by("email")
        member_emails = list(q.values_list("email", flat=True))
        return [self.owner.email] + member_emails

    # -- API key rotation and expiry governance (opt-in) ---------------

    def _lock_self(self) -> None:
        """Acquire a row lock on this project.

        Serializes governance mutations (rotation/revocation) per project,
        so they cannot interleave with each other.
        """
        list(Project.objects.select_for_update().filter(pk=self.pk))

    def _new_credential(self, slot: str) -> tuple["ApiKeyCredential", str]:
        """Generate and persist a new current credential for the slot."""
        prefix = "hcw_" if slot == "api_key" else "hcr_"
        key, key_hash = self._make_api_key(prefix)

        expires_at: datetime | None = None
        if settings.API_KEY_EXPIRATION_ENABLED:
            expires_at = now() + td(
                seconds=governance_seconds("API_KEY_LIFETIME")
            )

        cred = ApiKeyCredential(
            project=self,
            slot=slot,
            key_hash=key_hash,
            prefix=key_hash.split(".", 1)[0],
            status=ApiKeyCredential.Status.CURRENT,
            expires_at=expires_at,
        )
        cred.save()

        # Keep the legacy column in sync with the current key
        Project.objects.filter(pk=self.pk).update(**{slot: key_hash})
        setattr(self, slot, key_hash)
        return cred, key

    def create_api_credential(self, slot: str) -> str:
        """Generate the current key for an empty slot. Returns plaintext once."""
        with transaction.atomic():
            self._lock_self()
            if ApiKeyCredential.objects.filter(
                project=self, slot=slot, status=ApiKeyCredential.Status.CURRENT
            ).exists():
                raise ApiKeyError("The slot already has a current API key")
            return self._new_credential(slot)[1]

    def start_key_rotation(self, slot: str) -> str:
        """Rotate the slot's key, demoting the current key to "previous".

        The previous key keeps authenticating until the rotation window ends.
        Returns the new plaintext key (shown to the user exactly once).
        """
        with transaction.atomic():
            self._lock_self()
            if ApiKeyCredential.objects.filter(
                project=self, slot=slot, status=ApiKeyCredential.Status.PREVIOUS
            ).exists():
                raise RotationInProgressError(
                    "A key rotation is already in progress for this slot. "
                    "Wait for the transition window to end or revoke the "
                    "previous key before rotating again."
                )

            current = ApiKeyCredential.objects.filter(
                project=self, slot=slot, status=ApiKeyCredential.Status.CURRENT
            ).first()
            if current is None:
                raise NoCurrentKeyError("The slot has no current API key")

            current.status = ApiKeyCredential.Status.PREVIOUS
            current.window_expires_at = now() + td(
                seconds=governance_seconds("API_KEY_ROTATION_WINDOW")
            )
            current.save(update_fields=["status", "window_expires_at"])

            return self._new_credential(slot)[1]

    def finish_key_rotation(self, slot: str) -> bool:
        """Close the rotation window immediately, invalidating previous key."""
        with transaction.atomic():
            self._lock_self()
            n = ApiKeyCredential.objects.filter(
                project=self, slot=slot, status=ApiKeyCredential.Status.PREVIOUS
            ).update(
                status=ApiKeyCredential.Status.INVALID,
                invalid_reason=ApiKeyCredential.InvalidReason.WINDOW,
                window_expires_at=now(),
            )
            return n > 0

    def revoke_previous_key(self, slot: str) -> bool:
        """Revoke the previous key while a rotation window is open."""
        with transaction.atomic():
            self._lock_self()
            n = ApiKeyCredential.objects.filter(
                project=self, slot=slot, status=ApiKeyCredential.Status.PREVIOUS
            ).update(
                status=ApiKeyCredential.Status.INVALID,
                invalid_reason=ApiKeyCredential.InvalidReason.WINDOW,
                window_expires_at=now(),
            )
            return n > 0

    def revoke_current_key(self, slot: str) -> None:
        """Revoke the current key together with any previous key in window."""
        with transaction.atomic():
            self._lock_self()
            ApiKeyCredential.objects.filter(
                project=self, slot=slot, status=ApiKeyCredential.Status.PREVIOUS
            ).update(
                status=ApiKeyCredential.Status.INVALID,
                invalid_reason=ApiKeyCredential.InvalidReason.WINDOW,
                window_expires_at=now(),
            )
            ApiKeyCredential.objects.filter(
                project=self, slot=slot, status=ApiKeyCredential.Status.CURRENT
            ).update(
                status=ApiKeyCredential.Status.INVALID,
                invalid_reason=ApiKeyCredential.InvalidReason.REVOKED,
            )

            Project.objects.filter(pk=self.pk).update(**{slot: ""})
            setattr(self, slot, "")


@dataclass
class ApiAuthResult:
    """Outcome of a governance-enabled API key authentication."""

    accepted: bool
    expired: bool = False
    project: Project | None = None
    readonly: bool = False
    generation: str = "unknown"


class ApiKeyCredentialManager(models.Manager["ApiKeyCredential"]):
    def candidates_for(self, api_key: str) -> QuerySet["ApiKeyCredential"]:
        """Return credentials that could match the presented API key.

        Looks up hashed keys by the first 8 characters of their random part,
        and legacy plain text keys by exact equality. The caller is responsible
        for calling ApiKeyCredential.compare() and for checking slot access.
        """
        if api_key.startswith(("hcw_", "hcr_")) and len(api_key) == 32:
            prefix = api_key[4:12]
            return self.filter(Q(prefix=prefix) | Q(prefix="", key_hash=api_key))

        # Legacy plain text keys (32 characters, no "hcw_"/"hcr_" prefix)
        return self.filter(prefix="", key_hash=api_key)

    def authenticate(
        self, api_key: str, accept_rw: bool, accept_ro: bool, source: str
    ) -> ApiAuthResult:
        """Authenticate a presented API key against credentials.

        Runs in a single transaction and locks the candidate credential rows,
        so a concurrent rotation either commits before this call (old key is
        then accepted as "previous" while the window is open) or after it
        (old key accepted as "current"). There is no point in time where
        neither the old nor the new key is recognized.

        Always writes an ApiKeyAudit row for recognized-form keys and updates
        the usage counters of accepted credentials.
        """
        C = ApiKeyCredential.Status.CURRENT
        P = ApiKeyCredential.Status.PREVIOUS
        I = ApiKeyCredential.Status.INVALID
        RW = ApiKeyCredential.Slot.RW

        allowed_slots: list[str] = []
        if accept_rw:
            allowed_slots.append(ApiKeyCredential.Slot.RW)
        if accept_ro:
            allowed_slots.append(ApiKeyCredential.Slot.RO)

        inferred_slot: str
        if api_key.startswith("hcr_"):
            inferred_slot = ApiKeyCredential.Slot.RO
        elif api_key.startswith("hcw_"):
            inferred_slot = ApiKeyCredential.Slot.RW
        else:
            inferred_slot = ""
        inferred_prefix = api_key[4:12] if inferred_slot else ""

        with transaction.atomic():
            candidates = list(
                self.candidates_for(api_key)
                .filter(slot__in=allowed_slots, status__in=(C, P, I))
                .select_for_update()
            )
            matched = next((c for c in candidates if c.compare(api_key)), None)
            ts = now()

            if matched is None:
                # Only audit attempts with a recognizable, attributable key
                # form (hcw_/hcr_ prefix). Unrecognizable keys produce no
                # audit rows -- they cannot be grouped by key prefix.
                if inferred_slot:
                    ApiKeyAudit.objects.create(
                        project=None,
                        slot=inferred_slot,
                        key_prefix=inferred_prefix,
                        generation=ApiKeyAudit.Generation.UNKNOWN,
                        result=ApiKeyAudit.Result.REJECTED,
                        source=source,
                    )
                return ApiAuthResult(accepted=False)

            generation = (
                ApiKeyAudit.Generation.CURRENT
                if matched.status == C
                else ApiKeyAudit.Generation.PREVIOUS
            )
            audit_prefix = matched.prefix or inferred_prefix

            if matched.status == I:
                # A previous key invalidated at window end, or a current key
                # reaped after its grace, is reported as expired. A key revoked
                # explicitly is a plain wrong key.
                expired = matched.invalid_reason in (
                    ApiKeyCredential.InvalidReason.WINDOW,
                    ApiKeyCredential.InvalidReason.EXPIRED,
                )
                ApiKeyAudit.objects.create(
                    project=matched.project,
                    slot=matched.slot,
                    key_prefix=audit_prefix,
                    generation=generation,
                    result=(
                        ApiKeyAudit.Result.REJECTED_EXPIRED
                        if expired
                        else ApiKeyAudit.Result.REJECTED
                    ),
                    source=source,
                )
                return ApiAuthResult(accepted=False, expired=expired)

            state = matched.evaluate(ts)
            if state == "expired":
                ApiKeyAudit.objects.create(
                    project=matched.project,
                    slot=matched.slot,
                    key_prefix=audit_prefix,
                    generation=generation,
                    result=ApiKeyAudit.Result.REJECTED_EXPIRED,
                    source=source,
                )
                return ApiAuthResult(accepted=False, expired=True)

            accepted_result = (
                ApiKeyAudit.Result.ACCEPTED_EXPIRED
                if state == "grace"
                else ApiKeyAudit.Result.ACCEPTED
            )

            matched.call_count += 1
            matched.last_used_at = ts
            matched.last_source = source
            if matched.first_used_at is None:
                matched.first_used_at = ts
            matched.save(
                update_fields=[
                    "call_count",
                    "last_used_at",
                    "last_source",
                    "first_used_at",
                ]
            )
            ApiKeyAudit.objects.create(
                project=matched.project,
                slot=matched.slot,
                key_prefix=audit_prefix,
                generation=generation,
                result=accepted_result,
                source=source,
            )

            return ApiAuthResult(
                accepted=True,
                project=matched.project,
                readonly=matched.slot != RW,
                generation=generation,
            )


class ApiKeyCredential(models.Model):
    """A single API key value held in one of the project's key slots.

    Each (project, slot) pair has at most one current key and at most one
    previous (in rotation window) key. key_hash uses the existing
    "secret8.hmacdigest" storage format; rows migrated from plain text keys
    hold the plain text value with an empty prefix.
    """

    class Slot(models.TextChoices):
        RW = "api_key", "API key"
        RO = "api_key_readonly", "API key (read-only)"

    class Status(models.TextChoices):
        CURRENT = "c", "Current"
        PREVIOUS = "p", "Previous"
        INVALID = "i", "Invalid"

    class InvalidReason(models.TextChoices):
        # Rotation window ended (or the previous key was revoked in-window)
        WINDOW = "window", "Rotation window ended"
        # Current key revoked by a user (revoke takes previous key too)
        REVOKED = "revoked", "Revoked"
        # Current key past its expiry + grace, reaped by the prune task
        EXPIRED = "expired", "Expired"

    project = models.ForeignKey(
        Project, models.CASCADE, related_name="api_key_credentials"
    )
    slot = models.CharField(max_length=32, choices=Slot.choices)
    key_hash = models.CharField(max_length=128)
    prefix = models.CharField(max_length=8, blank=True, db_index=True)
    status = models.CharField(
        max_length=1, choices=Status.choices, default=Status.CURRENT, db_index=True
    )
    # Why an INVALID credential stopped authenticating (null while live)
    invalid_reason = models.CharField(
        max_length=16, choices=InvalidReason.choices, null=True, blank=True
    )

    created_at = models.DateTimeField(auto_now_add=True)
    # Set when the key is demoted to "previous": when the rotation window ends
    window_expires_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField(null=True, blank=True)

    first_used_at = models.DateTimeField(null=True, blank=True)
    last_used_at = models.DateTimeField(null=True, blank=True)
    last_source = models.CharField(max_length=16, blank=True)
    call_count = models.IntegerField(default=0)

    objects = ApiKeyCredentialManager()

    class Meta:
        constraints = (
            models.UniqueConstraint(
                fields=["project", "slot"],
                condition=Q(status="c"),
                name="accounts_apikey_one_current",
            ),
            models.UniqueConstraint(
                fields=["project", "slot"],
                condition=Q(status="p"),
                name="accounts_apikey_one_previous",
            ),
        )

    @property
    def masked(self) -> str:
        shown = "hcw_" if self.slot == ApiKeyCredential.Slot.RW else "hcr_"
        if self.prefix:
            return shown + self.prefix + "*" * 20
        if self.key_hash:
            # Legacy plain text keys are masked like in the existing UI
            return self.key_hash[:4] + "*" * (len(self.key_hash) - 4)
        return ""

    def compare(self, key: str) -> bool:
        """Check if the presented plain text key matches this credential."""
        if "." in self.key_hash:
            _, digest = self.key_hash.split(".", maxsplit=1)
            computed = hmac.digest(
                settings.SECRET_KEY.encode(), key.encode(), "sha256"
            )
            return hmac.compare_digest(computed.hex(), digest)

        # Legacy plain text credential
        return hmac.compare_digest(self.key_hash, key)

    def is_expired(self, ts: datetime) -> bool:
        return self.expires_at is not None and ts > self.expires_at

    def in_grace(self, ts: datetime) -> bool:
        """Return True if the key is expired but still inside the grace period."""
        if not settings.API_KEY_EXPIRATION_ENABLED or not self.is_expired(ts):
            return False
        grace = td(seconds=governance_seconds("API_KEY_EXPIRATION_GRACE"))
        assert self.expires_at is not None
        return ts <= self.expires_at + grace

    def window_is_open(self, ts: datetime) -> bool:
        if self.status != ApiKeyCredential.Status.PREVIOUS:
            return False
        return self.window_expires_at is not None and ts < self.window_expires_at

    def evaluate(self, ts: datetime) -> str:
        """Return the credential's effective state at time ts.

        One of:
        * "valid"          - accepted normally
        * "grace"          - expired but accepted during the grace period
        * "expired"        - rejected: window closed or past grace
        """
        if self.status == ApiKeyCredential.Status.PREVIOUS and not self.window_is_open(
            ts
        ):
            return "expired"

        if settings.API_KEY_EXPIRATION_ENABLED and self.expires_at is not None:
            grace_end = self.expires_at + td(
                seconds=governance_seconds("API_KEY_EXPIRATION_GRACE")
            )
            if ts >= grace_end:
                return "expired"
            if ts > self.expires_at:
                return "grace"

        return "valid"


class ApiKeyAudit(models.Model):
    """An API key authentication event.

    Stores only the slot, key prefix (the 8 masked characters), generation,
    result, source category and timestamp. Never stores key material.
    """

    class Generation(models.TextChoices):
        CURRENT = "current", "Current"
        PREVIOUS = "previous", "Previous"
        UNKNOWN = "unknown", "Unknown"

    class Result(models.TextChoices):
        ACCEPTED = "accepted", "Accepted"
        ACCEPTED_EXPIRED = "accepted_expired", "Accepted (expired, in grace)"
        REJECTED = "rejected", "Rejected"
        REJECTED_EXPIRED = "rejected_expired", "Rejected (expired)"

    class Source(models.TextChoices):
        HEADER = "header", "X-Api-Key header"
        BODY = "body", "request body"

    # Null for rejected attempts whose presented key matches no project, so
    # unauthorized probes are still recorded and grouped by key prefix.
    project = models.ForeignKey(
        Project, models.CASCADE, related_name="api_key_audits", null=True, blank=True
    )
    slot = models.CharField(max_length=32, blank=True)
    key_prefix = models.CharField(max_length=8, blank=True)
    generation = models.CharField(
        max_length=8, choices=Generation.choices, default=Generation.UNKNOWN
    )
    result = models.CharField(max_length=16, choices=Result.choices)
    source = models.CharField(max_length=16, choices=Source.choices)
    created_at = models.DateTimeField(default=now, db_index=True)


class Member(models.Model):
    class Role(models.TextChoices):
        READONLY = "r", "Read-only"
        REGULAR = "w", "Member"
        MANAGER = "m", "Manager"

    user = models.ForeignKey(User, models.CASCADE, related_name="memberships")
    project = models.ForeignKey(Project, models.CASCADE)
    transfer_request_date = models.DateTimeField(null=True, blank=True)
    role = models.CharField(max_length=1, default=Role.REGULAR, choices=Role.choices)

    class Meta:
        constraints = (
            models.UniqueConstraint(
                fields=["user", "project"], name="accounts_member_no_duplicates"
            ),
        )

    def can_accept(self) -> bool:
        return self.user.profile.can_accept(self.project)

    @property
    def is_rw(self) -> bool:
        return self.role in (Member.Role.REGULAR, Member.Role.MANAGER)


class Credential(models.Model):
    code = models.UUIDField(default=uuid.uuid4, unique=True)
    name = models.CharField(max_length=100)
    user = models.ForeignKey(User, models.CASCADE, related_name="credentials")
    created = models.DateTimeField(auto_now_add=True)
    data = models.BinaryField()
