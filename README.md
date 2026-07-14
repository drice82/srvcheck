# SrvCheck

面向多测试点的 Xray 订阅节点监控。服务端同步订阅并汇总状态，Docker 客户端从不同网络位置执行真实 Xray 代理探测。

## 架构

- `web`：Django、Gunicorn、HTMX 管理界面和客户端 API。
- `scheduler`：订阅同步、报告过期聚合、历史清理和 Bark 通知。
- `client`：独立 Docker 镜像，包含 Xray-core；缓存节点、执行检查并回报状态。

服务端不执行节点测试，也不再提供 TCP/HTTPS 监控。多个已启用测试点存在时，同一节点至少两个测试点报告异常才判定故障；只有一个测试点时直接采用该测试点结果。

## 服务端部署

```bash
cp .env.example .env
# 修改 SECRET_KEY、管理员密码、ALLOWED_HOSTS 和 CLIENT_API_TOKEN
docker compose up --build -d
docker compose ps
```

登录管理界面后：

1. 添加 Xray 订阅并同步节点。
2. 在“测试点”中预先登记每个客户端名称，例如“深圳测试点”。
3. 配置 Bark 通知。

节点可以在订阅页面临时编辑。保存后服务端会立即向全部启用测试点下发检查任务；下一次订阅同步会使用订阅内容覆盖临时编辑。

客户端 API 会返回完整节点分享链接，生产环境必须通过 HTTPS 暴露服务端。

## 客户端部署

在每个测试点复制仓库中的 `compose.client.yaml` 和客户端环境配置：

```bash
cp .env.client.example .env
# SERVER_URL 指向服务端；CLIENT_NAME 必须与网页中登记的名称完全一致
docker compose -f compose.client.yaml up --build -d
docker compose -f compose.client.yaml logs -f client
```

客户端每 60 秒使用 ETag 检查节点清单，测试间隔和超时由订阅配置下发。服务端断联时客户端继续使用持久化缓存测试，每个节点仅保留最新待上报周期结果；连接恢复后自动补报。

## API

客户端使用以下请求头：

```text
Authorization: Bearer <CLIENT_API_TOKEN>
X-Client-Name: <UTF-8 百分号编码后的测试点名称>
```

- `GET /api/v1/client/manifest`：节点清单，支持 ETag。
- `GET /api/v1/client/tasks`：待执行的手动检查任务。
- `POST /api/v1/client/results`：幂等批量结果上报。

## 升级说明

本版本迁移会删除 TCP/HTTPS 配置与历史，也会清空旧服务端产生的 Xray 测试历史。Xray 订阅和节点配置会保留，节点聚合状态重置为未知，等待客户端首次报告。
