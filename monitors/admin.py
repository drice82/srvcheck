from django.contrib import admin
from .models import CheckResult, HTTPMonitor, NotificationLog, NotificationSetting, TCPMonitor, XrayNode, XrayNodeSnapshot, XraySubscription
admin.site.register([TCPMonitor, HTTPMonitor, XraySubscription, XrayNode, XrayNodeSnapshot, CheckResult, NotificationSetting, NotificationLog])
