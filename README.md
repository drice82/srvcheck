# SrvCheck

单用户服务监控站，支持 TCP、HTTPS、Xray 订阅节点检查，并在状态改变时通过 Bark 通知。

## 启动

```bash
cp .env.example .env
# 编辑 .env，至少修改 SECRET_KEY、管理员密码和 ALLOWED_HOSTS
docker compose up --build -d
docker compose ps
```

访问 `http://服务器地址:8000`，使用 `.env` 中配置的管理员账户登录。

## 架构

- `web`：Django、Gunicorn、HTMX 管理界面
- `scheduler`：独立定时检查进程，同时包含 Xray-core
- 两个容器共享 SQLite 数据卷；只允许启动一个 scheduler

## 支持范围

- TCP：连接状态及耗时
- HTTPS：状态码、TLS 验证、重定向和响应关键词
- Xray：解析 VMess、VLESS、Trojan、Shadowsocks 订阅；VMess/VLESS/Trojan 执行真实代理探测
- Xray 出口 IP 使用分层状态快照：状态柱展示此前 7 个完整自然日和最近 24 小时，悬停可查看 IP 或异常状态
- Bark：故障和恢复状态改变通知；每天 8:00 与 20:00 发送整体监控概况（可在通知设置中开关）

当前 Shadowsocks 节点可以被同步和展示，但复杂加密参数的真实代理探测将在后续版本完善。

## 运维

```bash
docker compose logs -f web scheduler
docker compose restart scheduler
docker compose down
```

数据库位于 Docker volume `srvcheck-data`。正式升级前请先备份该卷中的 `db.sqlite3`。

小时快照保留当前小时及此前 23 小时；日快照保留今天和此前 7 个完整自然日。调度器每小时自动清理，避免为每次节点检查重复保存出口 IP。
