from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [("monitors", "0006_merge_stale_xray_nodes")]
    operations = [
        migrations.RemoveConstraint(
            model_name="xraynode",
            name="unique_subscription_node",
        ),
    ]
