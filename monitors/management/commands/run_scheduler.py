import asyncio
import signal
import time

from django.conf import settings
from django.core.management.base import BaseCommand
from django.utils import timezone

from monitors.models import XraySubscription
from monitors.services import (
    aggregate_all_nodes,
    cleanup_history,
    maybe_send_summary,
    save_subscription_result,
    synchronize_subscription,
)


class Command(BaseCommand):
    help = "运行订阅同步、结果聚合和通知调度器（只应启动一个实例）"

    def handle(self, *args, **options):
        self.running = True
        signal.signal(signal.SIGTERM, lambda *_: setattr(self, "running", False))
        signal.signal(signal.SIGINT, lambda *_: setattr(self, "running", False))
        self.stdout.write(self.style.SUCCESS("SrvCheck server scheduler started"))
        self.last_cleanup = 0
        self.last_aggregate = 0
        while self.running:
            try:
                self.tick()
            except Exception as exc:
                self.stderr.write(f"scheduler tick failed: {type(exc).__name__}: {exc}")
            time.sleep(settings.SCHEDULER_TICK_SECONDS)

    def tick(self):
        monotonic = time.monotonic()
        if monotonic - self.last_cleanup >= 3600:
            self.last_cleanup = monotonic
            self.run_periodic("cleanup", cleanup_history)
        if monotonic - self.last_aggregate >= 30:
            self.last_aggregate = monotonic
            self.run_periodic("aggregate", aggregate_all_nodes)
        now = timezone.now()
        subscriptions = XraySubscription.objects.filter(enabled=True).filter(next_sync_at__isnull=True) | XraySubscription.objects.filter(enabled=True, next_sync_at__lte=now)
        for subscription in subscriptions[:5]:
            try:
                nodes, error = asyncio.run(synchronize_subscription(subscription))
                save_subscription_result(subscription, nodes, error)
            except Exception as exc:
                self.stderr.write(
                    f"subscription sync failed ({subscription.pk} {subscription.name}): "
                    f"{type(exc).__name__}: {exc}"
                )
        maybe_send_summary()

    def run_periodic(self, name, callback):
        try:
            callback()
        except Exception as exc:
            self.stderr.write(f"scheduler {name} failed: {type(exc).__name__}: {exc}")
