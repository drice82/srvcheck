# SrvCheck

面向多测试点的 Xray 订阅节点、TCP 与 HTTPS 监控。服务端统一下发监控目标并汇总状态，Docker 客户端从不同网络位置执行真实探测并回报结果。

## 架构

- `web`：Django、Gunicorn、HTMX 管理界面和客户端 API。
- `scheduler`：订阅同步、报告过期聚合、历史清理和 Bark 通知。
- `client`：独立 Docker 镜像，包含 Xray-core；缓存监控目标、执行检查并回报状态。

服务端不执行任何探测：Xray 节点走 xray-core 代理探测，TCP 做连接探测，HTTPS 校验状态码范围与响应关键词，全部由测试点客户端完成后报告。多个已启用测试点存在时，同一目标至少两个测试点报告异常才判定故障；只有一个测试点时直接采用该测试点结果。

## 服务端部署

```bash
cp .env.example .env
# 修改 SECRET_KEY、管理员密码、ALLOWED_HOSTS 和 CLIENT_API_TOKEN
docker compose up --build -d
docker compose ps
```

登录管理界面后：

1. 在“Xray 监控”添加订阅并同步节点。
2. 在“TCP 监控”“HTTPS 监控”页面各自添加监控目标。
3. 在“测试点”中预先登记每个客户端名称，例如“深圳测试点”。
4. 配置 Bark 通知。

节点可以在订阅页面临时编辑。保存后服务端会立即向全部启用测试点下发检查任务；下一次订阅同步会使用订阅内容覆盖临时编辑。TCP/HTTPS 监控新增或编辑后同样会立即下发检查任务；编辑会重置聚合状态并清除该目标的旧报告。

客户端 API 会返回完整节点分享链接，生产环境必须通过 HTTPS 暴露服务端。

## 客户端部署

在每个测试点复制仓库中的 `compose.client.yaml` 和客户端环境配置：

```bash
cp .env.client.example .env
# SERVER_URL 指向服务端；CLIENT_NAME 必须与网页中登记的名称完全一致
docker compose -f compose.client.yaml up --build -d
docker compose -f compose.client.yaml logs -f client
```

客户端每 60 秒使用 ETag 检查监控目标清单（Xray 节点、TCP、HTTPS），测试间隔和超时由服务端配置下发。服务端断联时客户端继续使用持久化缓存测试，每个目标仅保留最新待上报周期结果；连接恢复后自动补报。

## API

客户端使用以下请求头：

```text
Authorization: Bearer <CLIENT_API_TOKEN>
X-Client-Name: <UTF-8 百分号编码后的测试点名称>
```

- `GET /api/v1/client/manifest`：监控目标清单（`nodes`、`tcp_monitors`、`https_monitors`，均带 `kind` 与检查参数），支持 ETag。
- `GET /api/v1/client/tasks`：待执行的手动检查任务，返回 `target_type`（xray/tcp/https）与 `target_id`。
- `POST /api/v1/client/results`：幂等批量结果上报，每条携带 `target_type` + `target_id`（旧客户端的 `node_id` 仍按 Xray 节点兼容处理）。

## 升级说明

本版本新增 TCP/HTTPS 监控（迁移 `0010`），Xray 订阅、节点与历史数据不受影响。请同时升级服务端与全部测试点客户端镜像：新服务端仍接受旧客户端的 Xray 上报，但旧客户端无法执行 TCP/HTTPS 检查。
