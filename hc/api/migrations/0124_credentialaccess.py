import django.db.models.deletion
import django.utils.timezone
from django.db import migrations, models

import hc.api.models


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0123_alter_channel_kind"),
    ]

    operations = [
        migrations.AlterField(
            model_name="channel",
            name="value",
            field=hc.api.models.CredentialField(blank=True),
        ),
        migrations.CreateModel(
            name="CredentialAccess",
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
                    "action",
                    models.CharField(
                        choices=[
                            ("read", "Read"),
                            ("decrypt", "Decrypt with old key"),
                            ("rotate", "Rotate"),
                        ],
                        max_length=10,
                    ),
                ),
                ("key_id", models.CharField(blank=True, max_length=64)),
                (
                    "created",
                    models.DateTimeField(default=django.utils.timezone.now),
                ),
                (
                    "channel",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        to="api.channel",
                    ),
                ),
            ],
            options={
                "indexes": [
                    models.Index(
                        fields=["channel", "created"],
                        name="api_credacc_channel",
                    ),
                    models.Index(fields=["created"], name="api_credacc_created"),
                ],
            },
        ),
    ]
