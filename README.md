# FreeCloud Console

Windows 11 桌面端的**多云免费额度统一控制台**：把腾讯云、AWS、Azure、Cloudflare 等厂商的免费额度、不间断 DDNS 与 AI 中转收口到一个本地界面里。

> 调研结论：全球范围内**没有**同时满足「统一纳管多厂商 + 不间断 DDNS + AI 中转 + 自带 UI + Win11 原生 + 安全/性能优先」的现成项目（详见 `../deliverables/gstack/feature-dev-multicloud-console-2026-11-15.md`）。最接近的是 `ddns-go / ddns-updater` 与 `New API / One API / OmniRoute` 的组合，但仍需多套控制台、多份凭据、多次部署 —— 正是要解决的「分散」痛点。

## 它是什么 / 不是什么

- 是：一台 Win11 机器上常驻的本地服务 + 系统自带 Edge/WebView2 无地址栏窗口（WebUI）。
- 是：多家 DNS 厂商的记录同步、统一 OpenAI 兼容中转端点、额度与熔断、审计与脱敏日志。
- 不是：云端 SaaS、多租户服务、破解/绕过厂商授权的工具、把免费额度转售或二次分发的系统。
- 不是：可替代各家厂商控制台的完整体；只覆盖 DDNS 与 AI 推理这两类高频免费额度用途。

## 运行要求

| 项目 | 要求 |
|---|---|
| 操作系统 | Windows 11（本机已验证） |
| 运行时 | Node.js **22 LTS 或更高**（零 npm 依赖，无需 `npm install`） |
| 界面 | 系统自带 Microsoft Edge / WebView2 Runtime（Win11 预装，本机已验证） |
| 权限 | 普通用户权限，**不需要管理员** |

## 快速开始

```bat
:: 方式一：双击运行
bin\start.cmd

:: 方式二：命令行
node src\main.js

:: 本机自检（不启动窗口）
node src\main.js --selftest

:: 自动化测试
node --test tests\smoke.test.js
```

`start.cmd` 会启动 watchdog → 拉起后台 core → 用独立 `--user-data-dir` 打开一个无地址栏窗口。首次导航由服务端下发一次性票据，页面自动完成两步握手；**任何 token 都不会出现在 URL、命令行、DOM、日志、磁盘或浏览器历史中**。

本地一键验证（自检 + 全量回归）：

```bat
scripts\verify.cmd
```

如果窗口被误关、或会话到期需要重新认证：

```bat
bin\start.cmd --restart
```

`--restart` **不会按 PID 结束进程**（Windows 会复用 PID，且旧 watchdog 可能立刻拉起新 core）。它改为写入一个带实例 nonce 的 `restart.request`，由**正在运行的 watchdog 自己校验后优雅退出**； nonce 不匹配或超时则放弃重启，不结束任何进程。

## 首次配置流程

1. **云厂商凭据**：下拉选择厂商（只能用预置枚举，不能填任意 URL），填入最小权限的子账号密钥 → 保存（DPAPI 加密）→ 「测试连通」。
2. **DDNS 记录**：填域名 / 主机记录 / 类型 / TTL，选厂商与对应凭据 → 添加 → 「立即检测并同步」。
3. **AI 中转**：在「本机中转密钥」卡片点「生成密钥」（**只显示一次**）→ 上游列表启用/排序 → 用统一端点调用。
4. **设置与安全**：DDNS 间隔、探测源共识数、日志级别、开机自启、审计、脱敏导出/导入、退出。开机自启开关会**真正写入/删除用户级启动项**（`%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\FreeCloudConsole.cmd`），无需管理员；也可用 `scripts\enable-autostart.cmd` / `disable-autostart.cmd` / `autostart-status.cmd` 独立操作。导入配置时，所有上游端点都会从服务端模板重建，不接受导入文件里的 `endpoint`。

### 各厂商凭据与最小权限

| 厂商 | 字段 | 建议权限 |
|---|---|---|
| Cloudflare | `apiToken` | 单 Zone 的 `Zone:Read` + `Zone:DNS Edit`；DDNS 记录必须 `proxied=false` |
| 腾讯云 DNSPod | `secretId` / `secretKey` | 仅授权 DNSPod `DescribeRecordList` / `ModifyRecord` / `CreateRecord` 的子账号 |
| AWS Route 53 | `accessKeyId` / `secretAccessKey`（可选 `sessionToken`） | 仅 `route53:ChangeResourceRecordSets` + `ListResourceRecordSets`，记录需填 `zoneId` |
| Azure DNS | `tenantId` / `clientId` / `clientSecret` / `subscriptionId` / `resourceGroup` | 服务主体仅授 DNS Zone Contributor |
| 本地演示 Mock | 无 | 不产生任何外联，用于离线验证全流程 |

Cloudflare Workers AI、Azure OpenAI、腾讯云混元、AWS Bedrock 的 AI 上游端点由**服务端模板**预置，界面不接受自定义 `base_url`。

### 调用 AI 中转

```bat
curl -X POST http://127.0.0.1:PORT/v1/chat/completions ^
  -H "Content-Type: application/json" ^
  -H "X-FCC-CSRF: 1" ^
  -H "Authorization: Bearer <本机中转密钥>" ^
  -d "{\"messages\":[{\"role\":\"user\",\"content\":\"你好\"}]}"
```

- 端点**默认关闭**：未生成密钥或密钥无效一律 401，绝不成为开放代理。
- 只监听 `127.0.0.1`，不提供 LAN/公网暴露。
- 故障转移仅限 5xx / 超时 / 不可达；**额度到量或 429 一律停止并告警，不切到其他上游**。
- 支持 `stream: true` 的 SSE 透传；上游响应头一律不透传（天然剥掉 `Set-Cookie`）。

## 安全设计

- **零第三方依赖**：只用 Node 22 内置模块，无 npm 供应链；不打包 Chromium，用系统 WebView2。
- **仅本机回环**：启动自检拒绝任何非 `127.0.0.1` 绑定；Host 严格等于 `127.0.0.1:<port>`（防 DNS rebinding）；Origin 同源校验；禁止 CORS；所有非 GET 请求需 `X-FCC-CSRF: 1`（`X-Local-CSRF` 为兼容别名）。
- **两步启动握手**：合法导航下发 `__bt` 票据（HttpOnly / `Path=/__bootstrap` / 5s），`POST /__bootstrap` 校验一次性状态、Sec-Fetch 与票据后换发会话级 `fcc_session` cookie；成功后端点永久关闭，重启才重开。窗口票据以首次导航起算，总窗口 30s 硬上限、最多重发 3 次且旧票立即失效。**会话令牌仅存内存，不写入磁盘**；启动时会清除旧版遗留的 `session.token`。
- **凭据**：Windows DPAPI（CurrentUser），每 provider 独立密文块，entropy 绑定 provider id 防块互换；明文只经匿名管道、不落盘/不进命令行/不进日志/不进响应；解密失败 fail-closed 并禁用该 provider 自动任务。掩码统一 `***` + SHA-256 指纹后 4 位，**绝不取原文后 4 位**。
- **凭据永不导出**：导出端点忽略 `includeCredentials`，恒为脱敏配置；导入后必须重新录入凭据。
- **按用途隔离的 SSRF 白名单**：所有外联经 `assertUpstream(url, purpose)`，仅 HTTPS、禁 IP 字面量 / userinfo / 自定义端口 / 云元数据地址，`redirect: 'error'` 不跟随 302。主机白名单拆成 `ai` / `dns` / `probe` 三组且**互不通用**——否则一个指向 IP 探测站的上游就会把厂商凭据发到第三方。配置导入、磁盘上的 `config.json` 与新建上游，都会强制用服务端模板重建 `endpoint/kind/auth`。
- **故障转移边界**：仅 5xx / 超时 / 不可达可切换；429、402，以及带 `Retry-After` / `X-RateLimit-*` / 结构化 `error.code|type` 配额语义的 5xx，**一律停止并告警**，不切到其他上游（防额度规避）。配额判定只读结构化信号，最多读 4KB 并立即清零。
- **响应**：CSP `default-src 'none'` + 逐项放行、`nosniff`、`no-referrer`、`no-store`、`frame-ancestors 'none'`；前端只用 `textContent`，无 `innerHTML`、无内联样式、无外部资源。
- **会话生命周期**：空闲 15 分钟或绝对 TTL 8 小时后服务端销毁会话并退出 core；watchdog 只拉起后台服务，**不自动重开界面、不自动重新认证**，必须由用户显式 `start.cmd --restart`；重启次数受持久化 C21 计数器（5 次/分钟）约束，超限 fail-closed。`/api/status` 如实上报 `idleTimeoutSec` / `absoluteTtlSec` / `expiresAt` / `lastActivityAt`，不把已实施的 TTL 显示成 0。
- **最小权限自启与重启**：自启只写一个带标记的 `.cmd` 到用户 Startup 目录（不写注册表、不提权、不起 COM/PowerShell）；停用只删除自己带标记的文件，绝不误删同名文件。`--restart` 由带 nonce 的本机请求文件驱动，不按裸 PID 结束进程。

## 性能设计

- 单进程 Node 事件循环 + 零依赖，冷启动只做一次 DPAPI 解密（本机中转密钥以 Buffer 常驻，请求路径不启动 PowerShell）。
- DDNS：多探测源共识、**IP 未变化不调用任何 DNS API**、指数退避、请求并发、状态持久化。
- AI 中转：流式 SSE 零缓冲透传、上游响应体 4MB 上限、请求体默认 1MB 上限、按 provider 日额度计数与熔断。
- UI：单条 SSE 连接事件驱动，不做轮询风暴；事件环形缓冲上限 200 条。

## 测试与自检

本机实测（2026-11-15）：

```
scripts\verify.cmd                -> 自检 6/6 + 回归 34/34，退出码 0
node --test tests\smoke.test.js   -> # tests 34 / # pass 34 / # fail 0
node src\main.js --selftest       -> { checks: { edgeOrWebView2, loopbackBind,
                                      dpapiRoundtrip, ssrfMetadataBlocked,
                                      ssrfPlainHttpBlocked,
                                      maskNeverUsesPlaintextSuffix } 全为 true,
                                      ok: true }
```

自检退出码要求 **6 项全为 true**（含 DPAPI 往返），任何一项失败即非零退出。

34 条断言覆盖：Host/Origin/CSRF、两步握手与 410、会话失效、C12 绑定自检、SSRF 白名单与脱敏掩码、fail-closed 中转、密钥生成/吊销、SSE、审计、DDNS 共识与跳过、解密失败、TC28 凭据错配，以及最终安全复核新增的 8 条：**按用途隔离的白名单**、伪造端点在凭据发出前被拒、导入端点重建、5xx 携带 `Retry-After` 判为额度耗尽且不转移、普通 5xx 仍可转移（对照组）、会话令牌不落盘并清理遗留、自检全项判定、开机自启真实接线与不误删他人文件。

## 目录结构

```
freecloud-console/
  bin/start.cmd                     启动入口（Node 版本校验 + watchdog）
  scripts/
    verify.cmd                     一键自检 + 34 条回归
    enable-autostart.cmd           用户态开机自启（无需管理员）
    disable-autostart.cmd          停用自启
    autostart-status.cmd           查询自启状态
  src/
    main.js                        watchdog / 单实例锁 / WebView2 窗口 / 自检 / 重启握手
    core.js                        组装、监听、会话 TTL、密钥缓存
    server.js                      HTTP 路由与四道安全门
    auth.js                        两步票据握手（令牌仅内存）
    autostart.js                   用户级自启项（纯文件，无子进程/注册表）
    secrets.js                     DPAPI 凭据保险箱
    telemetry.js                   SSE 与审计
    ddns.js                        DDNS 引擎
    ai-gateway.js                  AI 中转与熔断
    config.js / util.js
    providers/                     DNS 与 AI 厂商适配器、TC3/SigV4 签名
    ui/                            index.html / app.css / app.js
  tests/smoke.test.js
```

数据目录：`%LOCALAPPDATA%\FreeCloudConsole\`（`config.json` 脱敏配置、`vault-*.bin` 密文、`state.json`、`runtime.json`、`restart-state.json`、`app.lock`、`restart.request` 临时握手文件）。**不再写入 `session.token`**；旧版遗留文件在启动时自动删除。

## 已知局限（P1，发布前需处理或如实告知）

1. **同用户下任意进程可解密 DPAPI 密文**；缺少 Credential Manager 的按 target 系统级隔离、统一轮换与审计。换 Windows 用户或重装系统后凭据需重新录入。
2. **JS 字符串不可擦除**：已做到 Buffer `fill(0)`、明文不持久化、不进日志/导出/命令行，但无法保证堆或崩溃转储零残留；日志轮转与 WER/heap dump 需实机验证。
3. 空闲期间会话仍有效，可被同机进程或接触机器者调用（暴露窗口）；已用 15min 空闲 + 8h 绝对 TTL + 显式重认证缓解，但未做「任意时刻即时失效」。
4. 上游凭据与端点为各家公开 API 的适配实现，**未用真实云账号实机联调**；腾讯云混元与 AWS Bedrock 的协议映射需按账号实际开通的接口核对。
5. 无代码签名，首次运行可能触发 SmartScreen。辅助脚本均为 `.cmd`，不依赖 PowerShell 执行策略（DPAPI 内部调用 PowerShell 属程序自有路径，不需要用户改策略）。
6. 事件日志目前只有 200 条内存环形缓冲，无磁盘日志轮转与大小上限策略。
7. AI 中转要求调用方额外带 `X-FCC-CSRF: 1`，部分第三方 OpenAI 兼容客户端可能不支持自定义头。
8. DDNS 的 Webhook / Callback 类自定义端点本期明确不做（SSRF 面），列条件性 P1。
9. `--restart` 的实例 nonce 与 `restart.request` 都在用户态数据目录内；同用户下的其他进程可构造该文件令应用退出（DoS）。这与「同用户进程可解密 DPAPI」属于同一威胁等级，未做跨用户隔离。
10. 开机自启启动项会优先用登录 PATH 上的 `node.exe`，并把创建时的绝对路径作为兜底；若通过版本管理器迁移或卸载了原 Node，需重跑 `scripts\enable-autostart.cmd`。

## 合规边界（务必阅读）

- 只使用各厂商**官方提供的免费额度**，遵守各家 ToS；不要用于绕过授权、共享/转售额度、规避配额或二次分发（含 one-api 类二次分发形态）。
- AI 中转是本地便利工具，不改变模型厂商与用户之间的授权关系；调用量、内容合规与数据跨境责任由使用者承担。
- 免费额度、模型名称、API 版本会变动，请以厂商官方文档为准，定期核对 `src/config.js` 与 `src/providers/` 中的端点与版本。
- 本项目限个人自用、单机、非多租户；不对外分发凭据、不提供任何凭据导出或分享能力。

## 回滚

关闭应用 → 备份 `%LOCALAPPDATA%\FreeCloudConsole\` → 用上一版源码覆盖本目录 → 重新启动。若要彻底清除本地凭据，删除该目录下的 `vault-*.bin`（不可恢复，需重新录入）。若曾开启自启，先运行 `scripts\disable-autostart.cmd` 移除用户级启动项。
