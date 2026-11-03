# magpie-officeace-aksk

OpenCode / magpie provider 插件（双 provider）：**OfficeAce** 与 **CodeArts（码道）**——
华为云 AgentArts 的两个编码服务，用**同一对永久 AK/SK 直连**——无需浏览器 OAuth、
无需临时凭证、无需续期。账号一直可用，直到密钥本身被吊销。

> 协议来源：[tastypear/credgate](https://github.com/tastypear/credgate)（AK/SK 双签名 + 积分算术）、
> [magpie-community/codearts](https://github.com/magpie-community/plugins/tree/main/packages/codearts)（响应形状、chat 处理、积分窗口口径）、
> [Q-shuang-dot/officeace2api](https://github.com/Q-shuang-dot/officeace2api)（协议文档）。详见 [NOTICE](./NOTICE.md)。

## 为什么是 AK/SK

传统方式是浏览器 OAuth 登录 → 下发临时 AK/SK/SecurityToken（一天有效期）→ 到期前用 refresh token 续期。
本插件跳过浏览器：直接用账号的**永久 AK/SK** 完成鉴权，无任何临时状态需要维护。

| Provider | 控制面 | 推理 |
|---|---|---|
| `officeace-aksk` | `client-permission-validate`（SDK-HMAC-SHA256）换 model key/secret + 网关地址 | Basic 调 `/v2/chat/completions`；订阅/领取走 V11-HMAC-SHA256 |
| `codearts-aksk` | `statistics/plugin`（SDK-HMAC-SHA256 + `x-sdk-content-sha256`）校验并读套餐 | AK/SK 直签 `/api/v2/chat/completions`（SSE），模型清单来自 `/v1/model/builtin` |

两个 provider 用同一个华为云 IAM 账号的 AK/SK，各自登录（各存一份凭据），互不影响。

## 安装

```sh
git clone https://github.com/tastypear/magpie-officeace-aksk.git
magpie plugin add ./magpie-officeace-aksk
magpie plugin login officeace-aksk   # OfficeAce 卡：输入 AK 和 SK
magpie plugin login codearts-aksk    # CodeArts 卡：同一对 AK/SK
magpie provider test codearts-aksk
magpie quota                         # 查看额度
```

**AK/SK 申请**：华为云控制台「统一身份认证服务 IAM → 我的凭证 → 访问密钥」，
<https://console.huaweicloud.com/iam/?#/mine/accessKey> （新建访问密钥，下载
credentials.csv，取 Access Key Id 与 Secret Access Key）。

**与其他插件共存**：本插件的 provider id 是 `officeace-aksk` / `codearts-aksk`，
与 [theseaiying/magpie-officeace-plugin](https://github.com/theseaiying/magpie-officeace-plugin)
（OAuth 版 `officeace`）和社区 [codearts](https://github.com/magpie-community/plugins/tree/main/packages/codearts)
（OAuth 版 `codearts`）可以同时安装、互不冲突。

## OfficeAce（officeace-aksk）

- **对话**：OpenAI 兼容 `/v2/chat/completions`，Basic 鉴权；强制流式（网关对流式响应最好），
  非流式请求自动把 SSE 聚合回单个 `chat.completion` JSON；glm-5.3 族去掉 thinking 参数，
  `max_tokens` 给推理模型留思考余量；**始终思考的模型**（glm-5.3-flash 等，实测回
  `ModelArts.81001`「该模型始终思考，不支持关闭思考」）自动剥离客户端的关思考参数
  （`enable_thinking:false` / `reasoning_effort:none`），保留 magpie 映射的思考等级；
  清单外的同款模型遇到 81001 也会去参数重发一次兜底
- **额度**：`/v1/subscription` 每个桶一行明细（套餐、新人奖励、每日签到各自的剩余与到期时间，
  过期的折叠成文案），路由只看总余额的聚合窗口——单个先用完的桶（如每日签到当天扣完）
  不会把还有套餐积分的账号误判成耗尽
- **签到**：`/v1/subscription/bonus/claim` 一次幂等 POST 领取每日签到与新人奖励（需在
  magpie 设置里打开 `officeace-aksk` 的每日签到开关）
- **模型**：登录后从 `/v2/models` 实时拉取，取不到时回退静态清单
- 错误：积分耗尽改写成 `insufficient_quota` 并带 `X-Magpie-Sign-In: kept`（Basic key 不过期，不标记账号）

## CodeArts（codearts-aksk）

- **对话**：`/api/v2/chat/completions`，AK/SK 直签（SDK-HMAC-SHA256，多签
  `x-sdk-content-sha256`）；网关按 `x-ot-session-id` 限每账号 3 个并发会话
  （`TM.00001041`，插件内退避重试、超预算回 429 交给 magpie 转移）；超长工具名
  （>64 字符）自动缩短并在响应里还原；默认注入 `thinking` 让推理分到
  `reasoning_content`（模型拒绝时按原请求重发）；200 里嵌的错误按码改写（限流→429 等）
- **模型级权益拒绝**（403，如试用套餐不含 glm-5.3 时上游回
  `TM.000010051`「当前所选模型的使用权益已耗尽」）：改写成 magpie 的模型拒绝方言，
  路由**只冷却该模型**、账号其他模型照常；永久 AK/SK 永不标记「登录失效」
- **额度**按套餐类型分流（`package.is_token_package` / `is_credit_package`，官方字段）：
  - **积分制**：社区版口径——「总积分」唯一门控窗口，分桶 aside 明细，各批次自己的到期时间
  - **token 制**（如体验版）：官网口径是超 5M 后降低排队优先级、无硬上限（实测超额 46 倍
    仍可用）——窗口纯展示（aside 不门控），额度当作无限，上游报错时再按错误码特判
  - 都没有：只报套餐名，不误判为耗尽
- **模型**：`/v1/model/builtin` 实时拉取（视觉模型 `-vl` 不列，`enable=false` 不列），
  回退静态清单
- 并发 `maxConcurrency: 3`（网关会话上限）

## 配置

| 变量 | 默认 | 说明 |
|---|---|---|
| `OFFICEACE_CLOUD_BASE` | `https://agentarts.cn-southwest-2.myhuaweicloud.com` | OfficeAce 控制面基址（调试/测试用） |
| `CODEARTS_SNAP_HOST` | `https://snap-access.cn-north-4.myhuaweicloud.com` | CodeArts 网关基址（调试/测试用） |

## 开发与测试

```sh
node --test --test-force-exit officeace-aksk.test.mjs   # 15 个测试（签名 oracle + 假上游全链路）
node --test --test-force-exit codearts-aksk.test.mjs    # 8 个测试（签名 oracle + 假上游全链路）
```

## 许可与风险

MIT + 使用声明（见 [LICENSE](./LICENSE)、[NOTICE](./NOTICE.md)）。要点：仅供个人学习、研究与自用；
禁止商业用途、二次分发牟利、批量账号运营；与华为云/OfficeAce/CodeArts/magpie 无关联；账号风控风险自行承担。
