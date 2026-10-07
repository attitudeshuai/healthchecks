from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("api", "0123_alter_channel_kind")]

    operations = [
        migrations.CreateModel(
            name="RateLimitConfig",
            fields=[
                (
                    "id",
                    models.AutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "scope",
                    models.CharField(
                        blank=True,
                        choices=[
                            ("project", "Per project"),
                            ("account", "Per account (project owner)"),
                        ],
                        max_length=10,
                    ),
                ),
                (
                    "limit",
                    models.PositiveIntegerField(blank=True, null=True),
                ),
                (
                    "window_secs",
                    models.PositiveIntegerField(blank=True, null=True),
                ),
                ("updated", models.DateTimeField(auto_now=True)),
            ],
            options={"verbose_name": "write rate limit configuration"},
        ),
        migrations.CreateModel(
            name="RateLimitCounter",
            fields=[
                (
                    "id",
                    models.AutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("value", models.CharField(max_length=80, unique=True)),
                ("count", models.PositiveIntegerField(default=0)),
                ("window_start", models.DateTimeField()),
            ],
            options={
                "indexes": [
                    models.Index(
                        fields=["window_start"],
                        name="api_ratelim_window__92febc_idx",
                    )
                ],
            },
        ),
    ]
