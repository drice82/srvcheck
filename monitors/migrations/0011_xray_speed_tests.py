from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("monitors", "0010_tcp_https_monitors")]

    operations = [
        migrations.AddField(
            model_name="manualchecktask",
            name="task_type",
            field=models.CharField(
                choices=[("check", "检查"), ("speed", "测速")], default="check", max_length=10
            ),
        ),
        migrations.AddField(
            model_name="clientresult",
            name="result_type",
            field=models.CharField(
                choices=[("check", "检查"), ("speed", "测速")], default="check", max_length=10
            ),
        ),
        migrations.AddField(
            model_name="clientresult",
            name="download_mbps",
            field=models.FloatField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="clientresult",
            name="transferred_bytes",
            field=models.PositiveBigIntegerField(blank=True, null=True),
        ),
    ]
