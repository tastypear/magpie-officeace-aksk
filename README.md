# magpie-officeace-aksk

OpenCode / magpie provider 插件：**OfficeAce**（华为云 AgentArts 模型网关），
用**永久 AK/SK 直连**——无需浏览器 OAuth、无需临时凭证、无需续期。账号一直可用，
直到密钥本身被吊销。

> 协议来源：[tastypear/credgate](https://github.com/tastypear/credgate)（AK/SK 双签名 + 积分算术）、
> [theseaiying/magpie-officeace-plugin](https://github.com/theseaiying/magpie-officeace-plugin)（响应形状与 chat 处理）、
> [Q-shuang-dot/officeace2api](https://github.com/Q-shuang-dot/officeace2api)（协议文档）。详见 [NOTICE](./NOTICE.md)。

## 为什么是 AK/SK

传统方式是浏览器 OAuth 登录 → 下发临时 AK/SK/SecurityToken（一天有效期）→ 到期前用 refresh token 续期。
本插件跳过浏览器：直接用账号的**永久 AK/SK** 完成两级鉴权，无任何临时状态需要维护。

| 层 | 接口 | 鉴权 |
|---|---|---|
| 控制面 | `agentarts.<region>.myhuaweicloud.com/v1/claw/client-permission-validate` | `SDK-HMAC-SHA256`（永久 AK/SK） |
| 网关 | `modelgw-*.huaweicloud-agentarts.com/v1/subscription`、`/v1/subscription/bonus/claim` | `V11-HMAC-SHA256`（AK/SK 经区域 scope 派生） |
| 推理 | `modelgw-*.huaweicloud-agentarts.com/v2/chat/completions`、`/v2/models` | `Basic base64(model_app_key:model_app_secret)` |

流程：永久 AK/SK → `client-permission-validate` 拿 model key/secret + 网关地址 → Basic 调推理；
额度来自 `/v1/subscription` 的 `skus[].quotas[]`（套餐）与 `bonus_skus[]`（奖励）。

## 安装

```sh
git clone https://github.com/tastypear/magpie-officeace-aksk.git
magpie plugin add ./magpie-officeace-aksk
magpie plugin login officeace-aksk   # 输入 AK 和 SK
magpie provider test officeace-aksk
magpie quota                         # 查看积分
```

**AK/SK 申请**：华为云控制台「统一身份认证服务 IAM → 我的凭证 → 访问密钥」，
<https://console.huaweicloud.com/iam/?#/mine/accessKey> （新建访问密钥，下载
credentials.csv，取 Access Key Id 与 Secret Access Key）。

**与其他插件共存**：本插件的 provider id 是 `officeace-aksk`，与
[theseaiying/magpie-officeace-plugin](https://github.com/theseaiying/magpie-officeace-plugin)
（OAuth 版，id 为 `officeace`）可以同时安装、互不冲突。

登录时会用 AK/SK 调一次 `client-permission-validate` 校验：错误的密钥在此就会被拒绝，
通过后把 model key/secret + 网关地址存进账号。

## 功能

- **永久 AK/SK 登录**：magpie 提示输入 AK 与 SK（SK 用 password 类型输入），无浏览器、无回调
- **对话转发**：OpenAI 兼容 `/v2/chat/completions`，Basic 鉴权；强制流式（网关对流式响应最好），
  非流式请求自动把 SSE 聚合回单个 `chat.completion` JSON；glm-5.3 族去掉 thinking 参数，
  `max_tokens` 给推理模型留思考余量
- **额度**：`/v1/subscription` 汇总套餐 + 奖励剩余，过期桶不计，带 `runsOutAt`（最先到期的那批）
- **签到**：`/v1/subscription/bonus/claim` 一次幂等 POST 领取每日签到与新人奖励，按 before/after 差额上报
- **模型**：登录后从 `/v2/models` 实时拉取，取不到时回退静态清单（deepseek/glm/kimi/qwen/openpangu）
- 错误：积分耗尽改写成 `insufficient_quota` 并带 `X-Magpie-Sign-In: kept`（Basic key 不过期，不标记账号）

## 配置

| 变量 | 默认 | 说明 |
|---|---|---|
| `OFFICEACE_CLOUD_BASE` | `https://agentarts.cn-southwest-2.myhuaweicloud.com` | 控制面基址（调试/测试用） |

区域固定 `cn-southwest-2`（OfficeAce 当前所在区域）。

## 开发与测试

```sh
node --test --test-force-exit officeace-aksk.test.mjs   # 签名 oracle + 假上游全链路
```

## 许可与风险

MIT + 使用声明（见 [LICENSE](./LICENSE)、[NOTICE](./NOTICE.md)）。要点：仅供个人学习、研究与自用；
禁止商业用途、二次分发牟利、批量账号运营；与华为云/OfficeAce/magpie 无关联；账号风控风险自行承担。
