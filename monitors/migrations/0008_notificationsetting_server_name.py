from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("monitors", "0007_allow_duplicate_xray_nodes")]

    operations = [
        migrations.AddField(
            model_name="notificationsetting",
            name="server_name",
            field=models.CharField(
                default="SrvCheck服务器",
                help_text="用于区分通知来源，例如：新加坡-01",
                max_length=80,
                verbose_name="服务器标识",
            ),
        ),
    ]
