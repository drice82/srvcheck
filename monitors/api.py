import json
import secrets
import uuid
from functools import wraps
from urllib.parse import unquote

from django.conf import settings
from django.http import JsonResponse
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django.views.decorators.csrf import csrf_exempt

from .models import ManualCheckAssignment, TestPoint
from .services import manifest_payload, save_client_result


def client_api(view):
    @wraps(view)
    @csrf_exempt
    def wrapped(request, *args, **kwargs):
        expected = settings.CLIENT_API_TOKEN
        supplied = request.headers.get("Authorization", "")
        token = supplied[7:] if supplied.startswith("Bearer ") else ""
        if not expected or not secrets.compare_digest(token, expected):
            return JsonResponse({"error": "unauthorized"}, status=401)
        name = unquote(request.headers.get("X-Client-Name", "")).strip()
        try:
            point = TestPoint.objects.get(name=name, enabled=True)
        except TestPoint.DoesNotExist:
            return JsonResponse({"error": "unknown_or_disabled_test_point"}, status=403)
        TestPoint.objects.filter(pk=point.pk).update(last_seen_at=timezone.now())
        request.test_point = point
        return view(request, *args, **kwargs)

    return wrapped


@client_api
def manifest(request):
    if request.method != "GET":
        return JsonResponse({"error": "method_not_allowed"}, status=405)
    payload = manifest_payload()
    etag = f'"{payload["version"]}"'
    if request.headers.get("If-None-Match") == etag:
        response = JsonResponse({}, status=304)
    else:
        response = JsonResponse(payload, json_dumps_params={"ensure_ascii": False})
    response["ETag"] = etag
    response["Cache-Control"] = "private, no-cache"
    return response


@client_api
def tasks(request):
    if request.method != "GET":
        return JsonResponse({"error": "method_not_allowed"}, status=405)
    now = timezone.now()
    assignments = ManualCheckAssignment.objects.filter(
        test_point=request.test_point,
        completed_at__isnull=True,
        task__expires_at__gt=now,
        task__node__enabled=True,
        task__node__active_in_subscription=True,
        task__node__subscription__enabled=True,
    ).select_related("task", "task__node")
    return JsonResponse(
        {
            "tasks": [
                {
                    "id": str(assignment.task_id),
                    "node_id": assignment.task.node_id,
                    "expires_at": assignment.task.expires_at.isoformat(),
                }
                for assignment in assignments
            ]
        }
    )


@client_api
def results(request):
    if request.method != "POST":
        return JsonResponse({"error": "method_not_allowed"}, status=405)
    try:
        payload = json.loads(request.body)
        items = payload["results"]
        if not isinstance(items, list) or len(items) > 1000:
            raise ValueError("results must be a list with at most 1000 items")
    except (ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
        return JsonResponse({"error": "invalid_payload", "detail": str(exc)}, status=400)

    accepted, duplicates, rejected = [], [], []
    for raw in items:
        result_id = str(raw.get("result_id", ""))
        try:
            parsed = {
                "result_id": uuid.UUID(result_id),
                "node_id": int(raw["node_id"]),
                "task_id": uuid.UUID(raw["task_id"]) if raw.get("task_id") else None,
                "checked_at": parse_checked_at(raw["checked_at"]),
                "success": parse_bool(raw["success"]),
                "latency_ms": parse_optional_nonnegative_int(raw.get("latency_ms")),
                "proxy_ip": raw.get("proxy_ip") or None,
                "message": str(raw.get("message", "")),
            }
            _, created = save_client_result(request.test_point, parsed)
            (accepted if created else duplicates).append(result_id)
        except Exception as exc:
            rejected.append({"result_id": result_id, "error": f"{type(exc).__name__}: {str(exc)[:200]}"})
    return JsonResponse(
        {
            "accepted": accepted,
            "duplicates": duplicates,
            "rejected": rejected,
            "server_time": timezone.now().isoformat(),
        },
        status=200,
    )


def parse_checked_at(value):
    parsed = parse_datetime(str(value))
    if parsed is None:
        raise ValueError("invalid checked_at")
    if timezone.is_naive(parsed):
        parsed = timezone.make_aware(parsed)
    return parsed


def parse_bool(value):
    if not isinstance(value, bool):
        raise ValueError("success must be boolean")
    return value


def parse_optional_nonnegative_int(value):
    if value is None:
        return None
    parsed = int(value)
    if parsed < 0:
        raise ValueError("latency_ms must be nonnegative")
    return parsed
