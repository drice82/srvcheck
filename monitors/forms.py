from django import forms
from .models import HTTPMonitor, NotificationSetting, TCPMonitor, XrayNode, XraySubscription

class StyledForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            if isinstance(field.widget, forms.CheckboxInput):
                field.widget.attrs["class"] = "h-4 w-4 rounded border-slate-300 text-cyan-600"
            else:
                field.widget.attrs["class"] = "w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-slate-900 focus:border-cyan-500 focus:outline-none"

class TCPMonitorForm(StyledForm):
    class Meta:
        model = TCPMonitor
        fields = ["name", "host", "port", "interval_seconds", "timeout_seconds", "enabled"]

class HTTPMonitorForm(StyledForm):
    class Meta:
        model = HTTPMonitor
        fields = ["name", "url", "expected_status_min", "expected_status_max", "keyword", "verify_tls", "follow_redirects", "interval_seconds", "timeout_seconds", "enabled"]

class XraySubscriptionForm(StyledForm):
    class Meta:
        model = XraySubscription
        fields = ["name", "url", "update_interval_minutes", "check_interval_seconds", "timeout_seconds", "enabled"]

class XrayNodeForm(StyledForm):
    class Meta:
        model = XrayNode
        fields = ["name", "share_link", "interval_seconds", "timeout_seconds", "enabled"]
        labels = {"share_link": "节点分享链接", "interval_seconds": "检查间隔（秒）", "timeout_seconds": "超时（秒）"}
        widgets = {"share_link": forms.Textarea(attrs={"rows": 4})}

class NotificationSettingForm(StyledForm):
    class Meta:
        model = NotificationSetting
        fields = ["bark_url", "enabled", "server_name", "failure_threshold", "recovery_threshold", "group", "summary_enabled"]
