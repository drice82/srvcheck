from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("monitors", "0011_xray_speed_tests")]

    operations = [
        migrations.AddField(
            model_name="xraynode",
            name="exit_ip",
            field=models.GenericIPAddressField(
                blank=True, editable=False, null=True, verbose_name="出口 IP"
            ),
        ),
        migrations.AddField(
            model_name="xraynode",
            name="country_code",
            field=models.CharField(blank=True, editable=False, max_length=2, verbose_name="国家代码"),
        ),
        migrations.AddField(
            model_name="xraynode",
            name="company_name",
            field=models.CharField(blank=True, editable=False, max_length=255, verbose_name="公司名"),
        ),
        migrations.AddField(
            model_name="xraynode",
            name="ip_info_checked_at",
            field=models.DateTimeField(blank=True, editable=False, null=True),
        ),
    ]
