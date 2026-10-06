from __future__ import annotations

from typing import Any
from datetime import datetime, timezone

from django import forms
from django.core.exceptions import ValidationError


class TimestampField(forms.Field):
    def to_python(self, value: str | None) -> datetime | None:
        if value is None:
            return None

        try:
            value_int = int(value)
        except ValueError:
            raise ValidationError(message="Must be an integer")

        # 10000000000 is year 2286 (a sanity check)
        if value_int < 0 or value_int > 10000000000:
            raise ValidationError(message="Out of bounds")

        return datetime.fromtimestamp(value_int, timezone.utc)


class FlipsFiltersForm(forms.Form):
    start = TimestampField(required=False)
    end = TimestampField(required=False)
    seconds = forms.IntegerField(required=False, min_value=0, max_value=31536000)


class PingsFiltersForm(forms.Form):
    """Validates the pagination and time-window parameters of the pings API.

    All timestamps are UNIX timestamps (seconds) interpreted in UTC, using the
    same convention as the flips API.
    """

    PAGE_SIZE_MIN = 1
    PAGE_SIZE_MAX = 1000
    # Sanity check, same bound as in TimestampField (year 2286):
    TS_MAX = 10000000000

    count = forms.CharField(required=False)
    cursor = forms.CharField(required=False, max_length=200)
    start = forms.CharField(required=False)
    end = forms.CharField(required=False)

    def clean_count(self) -> int | None:
        raw = self.cleaned_data.get("count")
        if not raw:
            return None

        try:
            value = int(raw)
        except ValueError:
            raise ValidationError(message="count must be an integer")

        if value < self.PAGE_SIZE_MIN or value > self.PAGE_SIZE_MAX:
            raise ValidationError(
                message=(
                    f"count must be between {self.PAGE_SIZE_MIN} "
                    f"and {self.PAGE_SIZE_MAX}"
                )
            )

        return value

    def _clean_timestamp(self, name: str) -> datetime | None:
        raw = self.cleaned_data.get(name)
        if not raw:
            return None

        try:
            value = int(raw)
        except ValueError:
            raise ValidationError(message=f"{name} must be a UNIX timestamp")

        # 10000000000 is year 2286 (a sanity check)
        if value < 0 or value > self.TS_MAX:
            raise ValidationError(message=f"{name} is out of bounds")

        return datetime.fromtimestamp(value, timezone.utc)

    def clean_start(self) -> datetime | None:
        return self._clean_timestamp("start")

    def clean_end(self) -> datetime | None:
        return self._clean_timestamp("end")

    def clean(self) -> dict[str, Any]:
        cleaned = super().clean() or {}
        start = cleaned.get("start")
        end = cleaned.get("end")
        if start and end and start > end:
            raise ValidationError(message="start must not be greater than end")

        return cleaned

    def first_error(self) -> str:
        """Return a human-readable message of the first validation error."""
        for messages in self.errors.values():
            return str(messages[0])
        return "invalid query parameters"
