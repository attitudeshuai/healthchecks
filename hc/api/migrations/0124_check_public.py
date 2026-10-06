from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0123_alter_channel_kind"),
    ]

    operations = [
        migrations.AddField(
            model_name="check",
            name="public",
            field=models.BooleanField(default=True),
        ),
    ]
