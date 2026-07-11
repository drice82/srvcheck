FROM python:3.13-slim

ARG XRAY_VERSION=26.3.27
ARG TARGETARCH
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends curl unzip ca-certificates \
    && arch="${TARGETARCH:-amd64}" \
    && case "$arch" in amd64) xarch=64;; arm64) xarch=arm64-v8a;; *) echo "Unsupported arch: $arch"; exit 1;; esac \
    && curl -fsSL "https://github.com/XTLS/Xray-core/releases/download/v${XRAY_VERSION}/Xray-linux-${xarch}.zip" -o /tmp/xray.zip \
    && unzip /tmp/xray.zip xray -d /usr/local/bin \
    && chmod +x /usr/local/bin/xray \
    && rm -rf /var/lib/apt/lists/* /tmp/xray.zip
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN chmod +x /app/docker-entrypoint.sh
ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["gunicorn", "config.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "2", "--timeout", "60"]
