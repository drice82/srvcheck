from django.db import migrations


def merge_stale_xray_nodes(apps, schema_editor):
    XrayNode = apps.get_model("monitors", "XrayNode")
    XrayNodeSnapshot = apps.get_model("monitors", "XrayNodeSnapshot")
    CheckResult = apps.get_model("monitors", "CheckResult")

    identities = XrayNode.objects.values_list("subscription_id", "protocol", "name").distinct()
    for subscription_id, protocol, name in identities.iterator():
        group = list(XrayNode.objects.filter(
            subscription_id=subscription_id, protocol=protocol, name=name,
        ).order_by("pk"))
        active = [node for node in group if node.active_in_subscription]
        stale = [node for node in group if not node.active_in_subscription]
        if len(active) != 1 or not stale:
            continue

        target = active[0]
        for source in stale:
            for snapshot in XrayNodeSnapshot.objects.filter(node_id=source.pk).iterator():
                current = XrayNodeSnapshot.objects.filter(
                    node_id=target.pk, kind=snapshot.kind, bucket_start=snapshot.bucket_start,
                ).first()
                if current is None:
                    snapshot.node_id = target.pk
                    snapshot.save(update_fields=["node"])
                elif snapshot.checked_at > current.checked_at:
                    current.success = snapshot.success
                    current.proxy_ip = snapshot.proxy_ip
                    current.latency_ms = snapshot.latency_ms
                    current.checked_at = snapshot.checked_at
                    current.save(update_fields=["success", "proxy_ip", "latency_ms", "checked_at"])
            CheckResult.objects.filter(monitor_type="xray", monitor_id=source.pk).update(monitor_id=target.pk)
            source.delete()


class Migration(migrations.Migration):
    dependencies = [("monitors", "0005_summary_fields")]
    operations = [migrations.RunPython(merge_stale_xray_nodes, migrations.RunPython.noop)]
