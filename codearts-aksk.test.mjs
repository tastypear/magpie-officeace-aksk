import { test } from "node:test"
import assert from "node:assert/strict"
import { createServer } from "node:http"
import { createHash, createHmac } from "node:crypto"

const { _internal } = await import("./index.mjs")

const AK = "AKTEST", SK = "SKTEST"
const DT = "20261103T000000Z"

// ---- 独立 oracle（社区版 signRequestHuawei 的 JS 直译，无 security-token）----

const oSha = (s) => createHash("sha256").update(s, "utf8").digest("hex")
const oHmac = (key, data) => createHmac("sha256", key).update(data, "utf8").digest("hex")

function oSdkSign(host, path, method, body, extra, dt) {
  const hv = { host, "x-sdk-date": dt, ...extra }
  const names = Object.keys(hv).sort()
  const headerLines = names.map((n) => `${n}:${String(hv[n]).trim()}`)
  const uri = path.endsWith("/") ? path : path + "/"
  const payloadHash = oSha(body)
  const cr = [method.toUpperCase(), uri, "", headerLines.join("\n"), "", names.join(";"), payloadHash].join("\n")
  const sts = `SDK-HMAC-SHA256\n${dt}\n${oSha(cr)}`
  const auth = `SDK-HMAC-SHA256 Access=${AK}, SignedHeaders=${names.join(";")}, Signature=${oHmac(SK, sts)}`
  return { auth, names, hv }
}

test("caSign: GET 签 host/x-sdk-date/x-sdk-content-sha256，POST 加 content-type", () => {
  const url = "https://snap-access.cn-north-4.myhuaweicloud.com/snap-manager/v1/statistics/plugin"
  const get = _internal.caSign("GET", url, AK, SK)
  const oGet = oSdkSign(new URL(url).host, "/snap-manager/v1/statistics/plugin", "GET", "",
    { "x-sdk-content-sha256": oSha("") }, DT)
  // caSign 用当前时间，这里只比对结构：拆出日期后再与 oracle 同日期比对
  const dt = get["X-Sdk-Date"]
  assert.match(dt, /^\d{8}T\d{6}Z$/)
  const oNow = oSdkSign(new URL(url).host, "/snap-manager/v1/statistics/plugin", "GET", "",
    { "x-sdk-content-sha256": oSha("") }, dt)
  assert.equal(get.Authorization, oNow.auth)
  assert.equal(get["x-sdk-content-sha256"], oSha(""))
  assert.equal(get["content-type"], undefined, "GET 不签 content-type")

  const claimUrl = "https://snap-access.cn-north-4.myhuaweicloud.com/api/v2/chat/completions"
  const body = JSON.stringify({ model: "m", messages: [] })
  const post = _internal.caSign("POST", claimUrl, AK, SK, body)
  const oPost = oSdkSign(new URL(claimUrl).host, "/api/v2/chat/completions", "POST", body,
    { "x-sdk-content-sha256": oSha(body), "content-type": "application/json" }, post["X-Sdk-Date"])
  assert.equal(post.Authorization, oPost.auth)
  assert.equal(post["content-type"], "application/json")
})

// ---- usage 分流 ----

test("caUsageOf: token 制纯展示不门控（真实形状）", () => {
  const sub = {
    metrics: [
      { name: "usageDataChatMessages", value: -1, usage_token_num: 0, package_token_amount: 0, show: false },
      { name: "usageTokenChatMessages", value: 0, usage_token_num: 230069618, package_token_amount: 5000000, show: true },
    ],
    start_date: "2026-10-09", end_date: "2026-11-10",
    package: { spec_code: "codearts.agent.trial", package_name_cn: "体验版", is_token_package: true, is_credit_package: false },
  }
  const u = _internal.caUsageOf(sub, undefined)
  assert.equal(u.plan, "体验版")
  assert.equal(u.signIn, "kept")
  assert.equal(u.error, undefined)
  assert.equal(u.windows.length, 1)
  const w = u.windows[0]
  assert.equal(w.aside, true, "token 制窗口必须 aside：额度当作无限，不能门控")
  assert.equal(w.name, "Token 用量（软限）")
  assert.equal(w.amount, 230069618)
  assert.equal(w.limit, 5000000)
  assert.equal(w.used, 100, "46 倍超额钳到 100%（纯展示）")
  assert.match(w.display, /2\.3亿 \/ 500\.0万 tokens/)
  assert.equal(w.resetsAt, "2026-11-09T16:00:00.000Z", "end_date 按北京时区的当天零点")
})

test("caUsageOf: 积分制照抄社区版（总积分门控 + 分桶 aside + 批次 runsOut）", () => {
  const sub = {
    metrics: [
      { name: "usageTotalPackageCredit", package_credit_amount: 30000, package_credit_remain: 20000, package_credit_expiring_amount: 0 },
      { name: "usageBasicPackageCredit", package_credit_amount: 500, package_credit_remain: 0, package_credit_expiring_amount: 0 },
    ],
    end_date: "2026-11-30",
    package: { spec_code: "codearts.agent.pro", package_name_cn: "专业版", is_credit_package: true, is_token_package: false },
  }
  const batches = [
    { metric: "usageBasicPackageCredit", amount: 500, left: 0, expiresAt: Date.parse("2026-11-30T00:00:00Z") },
    { metric: "usageOnDemandPackageCredit", amount: 1000, left: 1000, expiresAt: Date.parse("2026-11-15T00:00:00Z") },
  ]
  const u = _internal.caUsageOf(sub, batches)
  assert.equal(u.plan, "专业版")
  const total = u.windows.find((w) => w.name === "总积分")
  assert.equal(total.aside, undefined, "总积分是唯一门控窗口")
  assert.equal(total.limit, 30000)
  assert.equal(total.amount, 10000)
  assert.ok(Math.abs(total.used - 10000 / 300) < 1e-9)
  assert.equal(total.resetsAt, "2026-11-30T00:00:00.000Z", "基础包批次到期 = 周期重置")
  // 总积分的 runsOut：除基础包外最先失效的批次（on demand 1000 @ 11-15）
  assert.equal(total.runsOut, 1000)
  assert.equal(total.runsOutAt, "2026-11-15T00:00:00.000Z")
  const basic = u.windows.find((w) => w.name === "基础积分包")
  assert.equal(basic.aside, true, "分桶明细不门控")
  assert.equal(basic.used, 100)
  assert.equal(u.windows[0].name, "总积分", "总积分排最前")
})

test("caUsageOf: 无指标只报套餐，不误判耗尽", () => {
  const u = _internal.caUsageOf({ package: { package_name_cn: "体验版" }, metrics: [] }, undefined)
  assert.equal(u.plan, "体验版")
  assert.equal(u.error, undefined)
  assert.deepEqual(u.windows, [])
  assert.equal(u.signIn, "kept")
})

// ---- 工具名缩短/还原 ----

test("工具名缩短与还原：超 64 字符按 55+hash 切，流式分片也能拼回", async () => {
  const long = "mcp__plugin_android-emulator_android-emulator__android_discover_project" // 71
  const body = { model: "m", messages: [{ role: "user", content: "hi" }], tools: [{ type: "function", function: { name: long, parameters: {} } }] }
  const names = _internal.caShortenToolNames(body)
  assert.ok(names, "长名字被缩短")
  const cut = body.tools[0].function.name
  assert.equal(cut.length, 64)
  assert.equal(cut.slice(0, 55), long.slice(0, 55))
  assert.equal(names.get(cut), long)

  // 整个 completion 还原
  const completion = { choices: [{ message: { tool_calls: [{ function: { name: cut } }] } }] }
  _internal.caRestoreToolNames(completion, names)
  assert.equal(completion.choices[0].message.tool_calls[0].function.name, long)

  // 流式：名字分两半发，也能拼回原样
  const half = Math.floor(cut.length / 2)
  const sse = [
    `data: ${JSON.stringify({ choices: [{ index: 0, delta: { role: "assistant", tool_calls: [{ index: 0, function: { name: cut.slice(0, half) } }] } }] })}`,
    `data: ${JSON.stringify({ choices: [{ index: 0, delta: { tool_calls: [{ index: 0, function: { name: cut.slice(half) } }] } }] })}`,
    "data: [DONE]",
  ].join("\n") + "\n"
  const stream = _internal.caRestoreToolNamesInStream(
    new ReadableStream({
      start(c) {
        c.enqueue(new TextEncoder().encode(sse))
        c.close()
      },
    }),
    names,
  )
  const out = await new Response(stream).text()
  // 名字分两半发：两个事件里的名字片段拼起来是原样
  const pieces = []
  for (const m of out.matchAll(/"name"\s*:\s*"((?:[^"\\]|\\.)*)"/g)) pieces.push(m[1])
  assert.equal(pieces.join(""), long, "流里工具名分片拼回原样")

  // 同一组名字切得稳定
  const body2 = { tools: [{ type: "function", function: { name: long } }], messages: [] }
  const names2 = _internal.caShortenToolNames(body2)
  assert.equal(body2.tools[0].function.name, cut)
  assert.ok(names2)
})

// ---- chat fetch（mock 上游）----

function setup() {
  return new Promise((resolve, reject) => {
    let handler = null
    const server = createServer((req, res) => {
      let raw = ""
      req.on("data", (c) => (raw += c))
      req.on("end", () => handler?.(req, res, raw))
    })
    server.listen(0, "127.0.0.1", () => {
      process.env.CODEARTS_SNAP_HOST = `http://127.0.0.1:${server.address().port}`
      import(`./index.mjs?ts=${Date.now()}`)
        .then((mod) => resolve({ server, mod, setHandler: (h) => { handler = h } }))
        .catch(reject)
    })
  })
}

const auth = { type: "api", key: AK, metadata: { sk: SK } }

test("loader fetch: 签名头/会话头注入、thinking、流式透传、非流式折叠", async () => {
  const { server, mod, setHandler } = await setup()
  const plugin = await mod.CodeArtsAkskPlugin()
  const loader = await plugin.auth.loader(async () => auth)
  assert.equal(loader.baseURL, `http://127.0.0.1:${server.address().port}/api/v2`)
  assert.equal(loader.maxConcurrency, undefined)

  const url = `http://127.0.0.1:${server.address().port}/api/v2/chat/completions`
  const LONG = "mcp__plugin_android-emulator_android-emulator__android_discover_project"
  let seen = null
  setHandler((req, res, raw) => {
    seen = { headers: req.headers, body: JSON.parse(raw) }
    res.writeHead(200, { "Content-Type": "text/event-stream" })
    // 用请求里被缩短的名字回一个工具调用
    const cut = seen.body.tools?.[0]?.function?.name ?? ""
    res.end(
      [
        `data: ${JSON.stringify({ id: "x", model: seen.body.model, choices: [{ index: 0, delta: { role: "assistant", content: "好" } }] })}`,
        `data: ${JSON.stringify({ id: "x", choices: [{ index: 0, delta: { tool_calls: [{ index: 0, function: { name: cut } }] } }] })}`,
        `data: ${JSON.stringify({ id: "x", choices: [{ index: 0, delta: {}, finish_reason: "stop" }], usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 } })}`,
        "data: [DONE]",
      ].join("\n") + "\n",
    )
  })

  // 流式请求：透传 SSE，工具名在流里还原
  const sres = await loader.fetch(url, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ model: "GLM-5.2", stream: true, messages: [{ role: "user", content: "hi" }], tools: [{ type: "function", function: { name: LONG, parameters: {} } }] }),
  })
  assert.equal(sres.status, 200)
  const stext = await sres.text()
  assert.ok(stext.includes(LONG), "流里的工具名还原成原样")
  assert.ok(seen.headers.authorization.startsWith("SDK-HMAC-SHA256 Access=AKTEST,"), "聊天用 AK/SK 直签")
  assert.equal(seen.headers["x-sdk-content-sha256"], createHash("sha256").update(JSON.stringify(seen.body)).digest("hex"))
  assert.ok(seen.headers["x-ot-session-id"], "会话头已注入")
  assert.equal(seen.headers["x-ot-parent-session-id"], "")
  assert.deepEqual(seen.body.thinking, { type: "enabled" }, "默认注入 thinking")
  assert.equal(seen.body.stream, true, "强制流式")
  const cut = seen.body.tools[0].function.name
  assert.equal(cut.length, 64, "超长工具名被缩短")

  // 非流式请求：折叠回单个 chat.completion
  const jres = await loader.fetch(url, {
    method: "POST", body: JSON.stringify({ model: "GLM-5.2", messages: [{ role: "user", content: "hi" }], tools: [{ type: "function", function: { name: LONG, parameters: {} } }] }),
  })
  assert.equal(jres.status, 200)
  const j = await jres.json()
  assert.equal(j.object, "chat.completion")
  assert.equal(j.choices[0].message.content, "好")
  assert.equal(j.choices[0].message.tool_calls[0].function.name, LONG, "折叠结果里工具名还原")
  assert.equal(j.usage.total_tokens, 2)

  // 会话 id 每请求稳定
  setHandler((req, res) => { res.writeHead(200, { "Content-Type": "text/event-stream" }); res.end('data: {"choices":[{"index":0,"delta":{"role":"assistant","content":"x"}}]}\ndata: [DONE]\n') })
  await loader.fetch(url, { method: "POST", body: JSON.stringify({ model: "m", stream: true, messages: [] }) })
  const sid1 = seen.headers["x-ot-session-id"]
  await loader.fetch(url, { method: "POST", body: JSON.stringify({ model: "m", stream: true, messages: [] }) })
  assert.equal(seen.headers["x-ot-session-id"], sid1, "同账号会话 id 稳定")
  server.close()
})

test("loader fetch: 会话上限重试、thinking 拒绝重发、401 标记、内嵌错误改写", async () => {
  const { server, mod, setHandler } = await setup()
  const plugin = await mod.CodeArtsAkskPlugin()
  const loader = await plugin.auth.loader(async () => auth)
  const url = `http://127.0.0.1:${server.address().port}/api/v2/chat/completions`

  // TM.00001041 一次 → 重试成功
  let n = 0
  setHandler((req, res) => {
    n += 1
    if (n === 1) {
      res.writeHead(200, { "Content-Type": "text/event-stream" })
      res.end(`data: ${JSON.stringify({ error_code: "TM.00001041", error_msg: "并发会话数已达上限(3个)" })}\n\n`)
      return
    }
    res.writeHead(200, { "Content-Type": "text/event-stream" })
    res.end('data: {"choices":[{"index":0,"delta":{"role":"assistant","content":"ok"}}]}\ndata: [DONE]\n')
  })
  const r1 = await loader.fetch(url, { method: "POST", body: JSON.stringify({ model: "m", stream: true, messages: [] }) })
  assert.equal(r1.status, 200, "会话上限后重试成功")
  assert.equal(n, 2)

  // thinking 被拒 → 去掉重发
  let bodies = []
  setHandler((req, res, raw) => {
    bodies.push(JSON.parse(raw))
    if (bodies.length === 1) {
      res.writeHead(400, { "Content-Type": "application/json" })
      res.end('{"error_code":"InferHub.001001017.400","error_msg":"thinking parameter is not supported"}')
      return
    }
    res.writeHead(200, { "Content-Type": "text/event-stream" })
    res.end('data: {"choices":[{"index":0,"delta":{"role":"assistant","content":"ok"}}]}\ndata: [DONE]\n')
  })
  const r2 = await loader.fetch(url, { method: "POST", body: JSON.stringify({ model: "glm-5.3", stream: true, messages: [] }) })
  assert.equal(r2.status, 200)
  assert.equal(bodies[1].thinking, undefined, "重发时去掉了注入的 thinking")
  assert.equal(bodies[0].thinking.type, "enabled")

  // 401 → X-Magpie-Sign-In: expired
  setHandler((req, res) => { res.writeHead(401, { "Content-Type": "application/json" }); res.end('{"error_code":"APIG.0301"}') })
  const r3 = await loader.fetch(url, { method: "POST", body: JSON.stringify({ model: "m", messages: [] }) })
  assert.equal(r3.status, 401)
  assert.equal(r3.headers.get("X-Magpie-Sign-In"), "expired")

  // 403（模型权益拒绝，glm-5.3 实测形状 TM.000010051）→ magpie 模型级拒绝方言：
  // 不带 X-Magpie-Sign-In（账号永不失效），正文命中 ModelUnserved 且避开 quotaWords
  // （quotaWords 会把账号级冷却），路由只冷却该模型
  setHandler((req, res) => {
    res.writeHead(403, { "Content-Type": "application/json" })
    res.end('{"error_code":"TM.000010051","error_msg":"多模态功能或当前所选模型的使用权益已耗尽，可选择如下模型: [GLM-5.2, openpangu-2.0-pro]。 可免费升级到积分套餐获取更多权益。"}')
  })
  const r3b = await loader.fetch(url, { method: "POST", body: JSON.stringify({ model: "glm-5.3", messages: [] }) })
  assert.equal(r3b.status, 403)
  assert.equal(r3b.headers.get("X-Magpie-Sign-In"), null, "403 不能标记账号失效（永久 AK/SK 无登录失效）")
  const b3b = await r3b.json()
  assert.match(b3b.error.message, /模型未开通：glm-5.3/, "命中 ModelUnserved（模型…未开通）")
  assert.match(b3b.error.message, /GLM-5.2/, "带上游给的可用模型清单")
  assert.ok(!/套餐|余额|额度|用量|上限/.test(b3b.error.message), "改写正文不能落 quotaWords（否则账号级冷却）")
  assert.equal(b3b.error.code, "TM.000010051")

  // 200 里嵌 429 错误 → 429
  setHandler((req, res) => {
    res.writeHead(200, { "Content-Type": "text/event-stream" })
    res.end(`data: ${JSON.stringify({ error_code: "InferHub.ModelArts.81111.429", error_msg: "rate limited" })}\n\n`)
  })
  const r4 = await loader.fetch(url, { method: "POST", body: JSON.stringify({ model: "m", messages: [] }) })
  assert.equal(r4.status, 429, "内嵌限流错误改写成 429")
  assert.match(await r4.text(), /rate limited/)

  // 200 里嵌其他错误 → 502
  setHandler((req, res) => {
    res.writeHead(200, { "Content-Type": "text/event-stream" })
    res.end(`data: ${JSON.stringify({ error_code: "InferHub.002002009.404", error_msg: "model is not registered" })}\n\n`)
  })
  const r5 = await loader.fetch(url, { method: "POST", body: JSON.stringify({ model: "m", messages: [] }) })
  assert.equal(r5.status, 400, ".404（模型不存在）按社区版口径映射为 400")
  server.close()
})

test("models/config/authorize/usage 钩子", async () => {
  const { server, mod, setHandler } = await setup()
  const plugin = await mod.CodeArtsAkskPlugin()
  const method = plugin.auth.methods[0]
  assert.equal(plugin.auth.provider, "codearts-aksk")
  assert.equal(plugin.auth.maxConcurrency, 3)
  assert.equal(method.type, "api")
  assert.equal(method.keyless, true)

  // authorize：statistics 校验
  setHandler((req, res) => {
    assert.ok(req.url.includes("/statistics/plugin"))
    res.writeHead(200, { "Content-Type": "application/json" })
    res.end(JSON.stringify({ metrics: [], package: { package_name_cn: "体验版", is_token_package: true } }))
  })
  const ok = await method.authorize({ ak: AK, sk: SK })
  assert.equal(ok.type, "success")
  assert.equal(ok.key, AK)
  assert.equal(ok.metadata.sk, SK)

  setHandler((req, res) => { res.writeHead(401, { "Content-Type": "application/json" }); res.end('{"error_code":"APIG.0301"}') })
  const bad = await method.authorize({ ak: AK, sk: "wrong-secret-123456" })
  assert.equal(bad.type, "failed")
  assert.match(bad.error, /校验失败/)

  // models：builtin 清单
  setHandler((req, res) => {
    assert.ok(req.url.includes("/v1/model/builtin"))
    assert.equal(req.headers["agent-type"], "PromptCenter")
    res.writeHead(200, { "Content-Type": "application/json" })
    res.end(JSON.stringify({
      count: 4,
      builtinModels: [
        { model_id: "GLM-5.2", model_name: "GLM-5.2", enable: true },
        { model_id: "kimi-k2.6-vl", model_name: "Kimi-K2.6-VL", enable: true },
        { model_id: "qwen3-max", model_name: "Qwen3 Max", enable: false },
        { model_id: "deepseek-v4-flash-0731", model_name: "DeepSeek V4 Flash 0731", enable: true },
      ],
    }))
  })
  const models = await plugin.provider.models({ id: "codearts-aksk", models: {} }, { auth })
  assert.ok(models["GLM-5.2"])
  assert.equal(models["GLM-5.2"].limit.context, 202752, "已知上下文窗口")
  assert.equal(models["kimi-k2.6-vl"], undefined, "视觉模型不列")
  assert.equal(models["qwen3-max"], undefined, "enable=false 不列")
  assert.equal(models["deepseek-v4-flash-0731"].name, "DeepSeek V4 Flash 0731", "名字按上游原样（-dddd 后缀只对 id 生效）")
  assert.ok(models["deepseek-v4-flash-0731"].limit.context, 1048576)

  const fallback = await plugin.provider.models({ id: "codearts-aksk", models: mod._internal.caStaticModels() }, { auth: { type: "api", key: "", metadata: {} } })
  assert.ok(fallback["glm-5.3-flash"], "无 auth 回退静态目录")

  // usage：token 制
  setHandler((req, res) => {
    res.writeHead(200, { "Content-Type": "application/json" })
    res.end(JSON.stringify({
      metrics: [{ name: "usageTokenChatMessages", usage_token_num: 1000, package_token_amount: 5000000, show: true }],
      end_date: "2026-11-10",
      package: { package_name_cn: "体验版", is_token_package: true, is_credit_package: false },
    }))
  })
  const usage = await plugin.auth.usage(async () => auth)
  assert.equal(usage.plan, "体验版")
  assert.equal(usage.windows.length, 1)
  assert.equal(usage.windows[0].aside, true)
  assert.equal(usage.windows[0].amount, 1000)
  assert.equal(usage.signIn, "kept")

  // config hook
  const cfg = {}
  await plugin.config(cfg)
  assert.equal(cfg.provider["codearts-aksk"].name, "CodeArts (AK/SK)")
  assert.equal(cfg.provider["codearts-aksk"].api, `http://127.0.0.1:${server.address().port}/api/v2`)
  assert.ok(cfg.provider["codearts-aksk"].models["GLM-5.2"])
  server.close()
})
