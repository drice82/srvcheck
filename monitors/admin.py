from django.contrib import admin

from .models import (
    ClientResult,
    ManualCheckAssignment,
    ManualCheckTask,
    NotificationLog,
    NotificationSetting,
    TestPoint,
    XrayNode,
    XrayNodeSnapshot,
    XraySubscription,
)

admin.site.register([
    XraySubscription, XrayNode, TestPoint, ClientResult, XrayNodeSnapshot,
    ManualCheckTask, ManualCheckAssignment, NotificationSetting, NotificationLog,
])
