from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('monitors', '0004_xraynodesnapshot'),
    ]

    operations = [
        migrations.AddField(
            model_name='notificationsetting',
            name='summary_enabled',
            field=models.BooleanField(default=True, help_text='每天 8:00 与 20:00 发送整体监控概况', verbose_name='定时概况通知'),
        ),
        migrations.AddField(
            model_name='notificationsetting',
            name='summary_last_sent_at',
            field=models.DateTimeField(blank=True, editable=False, null=True),
        ),
    ]
