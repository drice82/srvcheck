import uuid

import django.db.models.deletion
from django.db import migrations, models


def reset_nodes(apps, schema_editor):
    apps.get_model("monitors", "XrayNode").objects.update(
        status="unknown", last_checked_at=None, last_changed_at=None, incident_open=False
    )


class Migration(migrations.Migration):
    dependencies = [("monitors", "0008_notificationsetting_server_name")]

    operations = [
        migrations.DeleteModel(name="XrayNodeSnapshot"),
        migrations.DeleteModel(name="CheckResult"),
        migrations.DeleteModel(name="TCPMonitor"),
        migrations.DeleteModel(name="HTTPMonitor"),
        migrations.RemoveField(model_name="xraynode", name="interval_seconds"),
        migrations.RemoveField(model_name="xraynode", name="timeout_seconds"),
        migrations.RemoveField(model_name="xraynode", name="next_check_at"),
        migrations.RemoveField(model_name="xraynode", name="last_latency_ms"),
        migrations.RemoveField(model_name="xraynode", name="last_error"),
        migrations.RemoveField(model_name="xraynode", name="consecutive_successes"),
        migrations.RemoveField(model_name="xraynode", name="consecutive_failures"),
        migrations.AddField(
            model_name="xraynode",
            name="incident_open",
            field=models.BooleanField(default=False, editable=False),
        ),
        migrations.RemoveField(model_name="notificationsetting", name="failure_threshold"),
        migrations.RemoveField(model_name="notificationsetting", name="recovery_threshold"),
        migrations.AlterField(
            model_name="notificationsetting",
            name="server_name",
            field=models.CharField(
                default="SrvCheck服务器", help_text="例如：中心服务器", max_length=80, verbose_name="服务器标识"
            ),
        ),
        migrations.CreateModel(
            name="TestPoint",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("name", models.CharField(max_length=120, unique=True, verbose_name="测试点名称")),
                ("enabled", models.BooleanField(default=True, verbose_name="启用")),
                ("last_seen_at", models.DateTimeField(blank=True, editable=False, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={"ordering": ["name"]},
        ),
        migrations.CreateModel(
            name="ManualCheckTask",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("expires_at", models.DateTimeField(db_index=True)),
                (
                    "node",
                    models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="manual_tasks", to="monitors.xraynode"),
                ),
            ],
            options={"ordering": ["-created_at"]},
        ),
        migrations.CreateModel(
            name="ManualCheckAssignment",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("completed_at", models.DateTimeField(blank=True, null=True)),
                (
                    "task",
                    models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="assignments", to="monitors.manualchecktask"),
                ),
                (
                    "test_point",
                    models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="manual_assignments", to="monitors.testpoint"),
                ),
            ],
            options={
                "constraints": [
                    models.UniqueConstraint(fields=("task", "test_point"), name="unique_manual_task_test_point")
                ]
            },
        ),
        migrations.CreateModel(
            name="ClientResult",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("result_id", models.UUIDField(default=uuid.uuid4, editable=False, unique=True)),
                ("success", models.BooleanField()),
                ("latency_ms", models.PositiveIntegerField(blank=True, null=True)),
                ("proxy_ip", models.GenericIPAddressField(blank=True, null=True)),
                ("message", models.CharField(blank=True, max_length=500)),
                ("checked_at", models.DateTimeField()),
                ("received_at", models.DateTimeField(auto_now_add=True, db_index=True)),
                (
                    "node",
                    models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="client_results", to="monitors.xraynode"),
                ),
                (
                    "task",
                    models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="results", to="monitors.manualchecktask"),
                ),
                (
                    "test_point",
                    models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="results", to="monitors.testpoint"),
                ),
            ],
            options={
                "ordering": ["-received_at"],
                "indexes": [models.Index(fields=["node", "test_point", "-received_at"], name="client_result_latest_idx")],
            },
        ),
        migrations.CreateModel(
            name="XrayNodeSnapshot",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("kind", models.CharField(choices=[("hourly", "小时"), ("daily", "每日")], max_length=10)),
                ("bucket_start", models.DateTimeField(db_index=True)),
                ("success", models.BooleanField()),
                ("proxy_ip", models.GenericIPAddressField(blank=True, null=True)),
                ("latency_ms", models.PositiveIntegerField(blank=True, null=True)),
                ("message", models.CharField(blank=True, max_length=500)),
                ("checked_at", models.DateTimeField()),
                (
                    "node",
                    models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="snapshots", to="monitors.xraynode"),
                ),
                (
                    "test_point",
                    models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="snapshots", to="monitors.testpoint"),
                ),
            ],
            options={
                "ordering": ["-bucket_start"],
                "indexes": [models.Index(fields=["kind", "bucket_start"], name="xray_client_snap_bucket_idx")],
                "constraints": [
                    models.UniqueConstraint(
                        fields=("node", "test_point", "kind", "bucket_start"),
                        name="unique_xray_client_snapshot_bucket",
                    )
                ],
            },
        ),
        migrations.RunPython(reset_nodes, migrations.RunPython.noop),
    ]
