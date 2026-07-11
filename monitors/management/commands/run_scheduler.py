import asyncio
import signal
import time
from django.conf import settings
from django.core.management.base import BaseCommand
from django.utils import timezone
from monitors.models import XraySubscription
from monitors.services import cleanup_history, due_monitors, execute_checks, save_outcome, save_subscription_result, synchronize_subscription

class Command(BaseCommand):
    help = "运行服务检查调度器（只应启动一个实例）"
    def handle(self, *args, **options):
        self.running = True
        signal.signal(signal.SIGTERM, lambda *_: setattr(self, "running", False))
        signal.signal(signal.SIGINT, lambda *_: setattr(self, "running", False))
        self.stdout.write(self.style.SUCCESS("SrvCheck scheduler started"))
        self.last_cleanup = 0
        while self.running:
            try:
                self.tick()
            except Exception as exc:
                self.stderr.write(f"scheduler tick failed: {type(exc).__name__}: {exc}")
            time.sleep(settings.SCHEDULER_TICK_SECONDS)
    def tick(self):
        if time.monotonic() - self.last_cleanup >= 3600:
            cleanup_history()
            self.last_cleanup = time.monotonic()
        now = timezone.now()
        subscriptions = XraySubscription.objects.filter(enabled=True).filter(next_sync_at__isnull=True) | XraySubscription.objects.filter(enabled=True, next_sync_at__lte=now)
        for subscription in subscriptions[:5]:
            nodes, error = asyncio.run(synchronize_subscription(subscription))
            save_subscription_result(subscription, nodes, error)
        items = due_monitors()
        if items:
            for kind, obj, outcome in asyncio.run(execute_checks(items)):
                save_outcome(kind, obj, outcome)
