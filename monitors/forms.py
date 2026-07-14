from django import forms

from .checkers import decode_subscription
from .models import NotificationSetting, TestPoint, XrayNode, XraySubscription


class StyledForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            if isinstance(field.widget, forms.CheckboxInput):
                field.widget.attrs["class"] = "h-4 w-4 rounded border-slate-300 text-cyan-600"
            else:
                field.widget.attrs["class"] = (
                    "w-full rounded-lg border border-slate-300 bg-white px-3 py-2 "
                    "text-slate-900 focus:border-cyan-500 focus:outline-none"
                )


class XraySubscriptionForm(StyledForm):
    class Meta:
        model = XraySubscription
        fields = ["name", "url", "update_interval_minutes", "check_interval_seconds", "timeout_seconds", "enabled"]


class TestPointForm(StyledForm):
    class Meta:
        model = TestPoint
        fields = ["name", "enabled"]


class XrayNodeForm(StyledForm):
    class Meta:
        model = XrayNode
        fields = ["name", "share_link"]
        labels = {"share_link": "节点分享链接"}
        help_texts = {"share_link": "保存后会立即通知全部测试点检查；下次同步订阅时会恢复订阅中的配置。"}
        widgets = {"share_link": forms.Textarea(attrs={"rows": 5})}

    def clean_share_link(self):
        value = self.cleaned_data["share_link"].strip()
        nodes = decode_subscription(value)
        if len(nodes) != 1:
            raise forms.ValidationError("请输入一个有效的 VMess、VLESS、Trojan 或 Shadowsocks 分享链接。")
        self.parsed_node = nodes[0]
        return value


class NotificationSettingForm(StyledForm):
    class Meta:
        model = NotificationSetting
        fields = ["bark_url", "enabled", "server_name", "group", "summary_enabled"]
