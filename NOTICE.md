# 第三方来源与致谢

本插件的协议实现参考了下列开源项目。凡直接借鉴代码、常量或算法的地方，
均在对应源码注释中标注来源；本文件汇总全部来源、作者、许可证与具体借鉴内容。

> 本插件与下表任何项目及其背后的公司均无隶属关系。

## 1. credgate（AK/SK 直连认证与积分算术的主要来源）

- 地址：https://github.com/tastypear/credgate（私有）
- 作者：tastypear
- 许可证：MIT
- 借鉴内容：
  - 两套华为云签名：控制面 SDK-HMAC-SHA256、订阅 API V11-HMAC-SHA256
    （签名 key 经区域 scope 派生：HMAC(HMAC(AK,SK), scope+0x01)[:32] 的十六进制串）
  - 永久 AK/SK 直连流程：client-permission-validate 换 model key/secret 与网关地址，
    推理走 Basic，订阅/领取走 V11，全程无临时 token
  - 积分算术：套餐 skus[].quotas[]（sku_value/current_value）+ 奖励 bonus_skus[]
    （points/current_value），过期桶不计

## 2. magpie-officeace-plugin（协议响应形状与 chat 处理）

- 地址：https://github.com/theseaiying/magpie-officeace-plugin
- 作者：theseaiying
- 许可证：MIT
- 借鉴内容（OAuth 变体，本插件仅取其协议层）：
  - client-permission-validate 响应解析（model_info.model_auth_info.model_app_key/secret、
    model_api_url_base）
  - /v2/chat/completions 的 body 改写（fitBody：强制 stream、include_usage、
    glm-5.3 族去 thinking 参数、max_tokens +1024、temperature/top_p 钳位）
  - 非流式请求的 SSE 聚合（aggregated）
  - 积分耗尽的错误改写（X-Magpie-Sign-In: kept + insufficient_quota）
  - /v1/subscription 的 usageOf 窗口（used%、runsOutAt）、bonus 领取的 before/after 差额
  - 模型静态清单（deepseek/glm/kimi/qwen/openpangu）与 /v2/models 解析

## 3. officeace2api（协议文档与签名参照）

- 地址：https://github.com/Q-shuang-dot/officeace2api
- 作者：Q-shuang-dot
- 许可证：MIT
- 借鉴内容：OfficeAce 桌面客户端解包整理的端点、签名算法、模型清单与 chat 行为
  （经上述两个项目间接引用）

## 4. magpie-community/codearts（CodeArts 协议与 chat 处理）

- 地址：https://github.com/magpie-community/plugins/tree/main/packages/codearts
- 作者：magpie-community 及贡献者
- 许可证：MIT
- 借鉴内容（CodeArts 分支）：
  - snap-access 签名（SDK-HMAC-SHA256 + x-sdk-content-sha256、canonical request 格式）
  - chat 处理：默认注入 thinking 分离 reasoning、强制流式、超长工具名缩短/流式还原
    （>64 字符按 55+8hex 切）、TM.00001041 会话上限重试、200 内嵌错误按码改写
  - 积分制用量窗口口径（总积分门控 + 分桶 aside + 批次到期 runsOut）
  - 静态模型目录与上下文窗口
  - 区别：本插件用永久 AK/SK 直签（社区版为 OAuth+STS 临时凭证）；token 制套餐
    （is_token_package）窗口纯展示不门控（社区版只认积分指标，会把 token 制账号
    误判为「无积分额度」）

## 5. magpie（插件接口）

- 地址：https://github.com/yetone/magpie
- 许可证：MIT
- 借鉴内容：OpenCode v1 插件规范与 magpie 专有钩子（auth.usage/checkin、
  X-Magpie-Sign-In、usage 窗口字段语义）
