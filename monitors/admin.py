from django.contrib import admin

from .models import (
    ClientResult,
    HTTPSMonitor,
    ManualCheckAssignment,
    ManualCheckTask,
    MonitorSnapshot,
    NotificationLog,
    NotificationSetting,
    TCPMonitor,
    TestPoint,
    XrayNode,
    XrayNodeSnapshot,
    XraySubscription,
)

admin.site.register([
    XraySubscription, XrayNode, TCPMonitor, HTTPSMonitor, TestPoint, ClientResult,
    XrayNodeSnapshot, MonitorSnapshot, ManualCheckTask, ManualCheckAssignment,
    NotificationSetting, NotificationLog,
])
