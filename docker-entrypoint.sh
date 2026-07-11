#!/bin/sh
set -eu
mkdir -p /app/data /app/staticfiles
python manage.py migrate --noinput
python manage.py collectstatic --noinput
if [ -n "${DJANGO_SUPERUSER_USERNAME:-}" ] && [ -n "${DJANGO_SUPERUSER_PASSWORD:-}" ]; then
  python manage.py shell -c "from django.contrib.auth import get_user_model; U=get_user_model(); u,created=U.objects.get_or_create(username='$DJANGO_SUPERUSER_USERNAME', defaults={'is_staff':True,'is_superuser':True}); u.set_password('$DJANGO_SUPERUSER_PASSWORD'); u.is_staff=True; u.is_superuser=True; u.save() if created or not u.check_password('$DJANGO_SUPERUSER_PASSWORD') else None"
fi
exec "$@"
