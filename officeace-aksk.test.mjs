import { test } from "node:test"
import assert from "node:assert/strict"
import { createServer } from "node:http"
import { createHash, createHmac } from "node:crypto"

const { _internal, OfficeAceAkskPlugin } = await import("./index.mjs")

// ---- 独立签名 oracle（credgate signing.py 的 JS 直译，与插件实现独立） ----
// 用来验证插件的 signSdk/signV11 正确移植了算法，尤其是 V11 的「hex 串当 key」怪癖。

const oSha = (s) => createHash("sha256").update(s, "utf8").digest("hex")
const oHmac = (key, data) => createHmac("sha256", key).update(data, "utf8").digest("hex")

function oSdk(ak, sk, host, path, method, body, extra, dt) {
  const hv = { host, "x-sdk-date": dt, ...extra }
  const names = Object.keys(hv).sort()
  const ch = names.map((n) => `${n}:${String(hv[n]).trim()}\n`).join("")
  const uri = path.endsWith("/") ? path : path + "/"
  const cr = [method.toUpperCase(), uri, "", ch, names.join(";"), oSha(body)].join("\n")
  const sts = ["SDK-HMAC-SHA256", dt, oSha(cr)].join("\n")
  const auth = `SDK-HMAC-SHA256 Access=${ak}, SignedHeaders=${names.join(";")}, Signature=${oHmac(sk, sts)}`
  const headers = { Authorization: auth, "X-Sdk-Date": dt }
  for (const n of names) if (n !== "host" && n !== "x-sdk-date") headers[n] = hv[n]
  return headers
}

function oV11(ak, sk, host, path, method, body, contentType, dt, region = "cn-southwest-2", service = "apic") {
  const hv = { host, "x-sdk-date": dt }
  if (contentType) hv["content-type"] = contentType
  const names = Object.keys(hv).sort()
  const ch = names.map((n) => `${n}:${String(hv[n]).trim()}\n`).join("")
  const uri = path.endsWith("/") ? path : path + "/"
  const cr = [method.toUpperCase(), uri, "", ch, names.join(";"), oSha(body)].join("\n")
  const scope = `${dt.slice(0, 8)}/${region}/${service}`
  const sts = ["V11-HMAC-SHA256", dt, scope, oSha(cr)].join("\n")
  // credgate 的派生：step1=HMAC(AK,SK)；signingKey=HMAC(step1, scope+0x01)[:32] 的十六进制串
  const step1 = createHmac("sha256", ak).update(sk, "utf8").digest()
  const seed = Buffer.concat([Buffer.from(scope, "utf8"), Buffer.from([1])])
  const signingKey = createHmac("sha256", step1).update(seed).digest().subarray(0, 32).toString("hex")
  // 怪癖：最终签名以 hex 串的 utf8 字节为 key（不是原始 32 字节）
  const sig = oHmac(signingKey, sts)
  const auth = `V11-HMAC-SHA256 Credential=${ak}/${scope}, SignedHeaders=${names.join(";")}, Signature=${sig}`
  const headers = { Authorization: auth, "X-Sdk-Date": dt }
  if (contentType) headers["Content-Type"] = contentType
  return headers
}

const DT = "20261101T000000Z"
const AK = "AKTEST", SK = "SKTEST"

test("signSdk 与 credgate 风格 oracle 字节一致（CPV: host + x-sdk-date + x-subscription-type）", () => {
  const url = "https://agentarts.cn-southwest-2.myhuaweicloud.com/v1/claw/client-permission-validate"
  const mine = _internal.signSdk({ method: "GET", url, ak: AK, sk: SK, headers: { "x-subscription-type": "v2" }, sdkDateOverride: DT })
  const oracle = oSdk(AK, SK, new URL(url).host, "/v1/claw/client-permission-validate", "GET", "", { "x-subscription-type": "v2" }, DT)
  assert.equal(mine.Authorization, oracle.Authorization)
  assert.equal(mine["X-Sdk-Date"], DT)
  assert.equal(mine["x-subscription-type"], "v2")
  assert.match(mine.Authorization, /^SDK-HMAC-SHA256 Access=AKTEST, SignedHeaders=host;x-sdk-date;x-subscription-type, Signature=[0-9a-f]{64}$/)
})

test("signV11 与 oracle 一致，且 GET 不带 content-type", () => {
  const url = "https://modelgw-0004.officeace.cn-southwest-2.huaweicloud-agentarts.com/v1/subscription"
  const mine = _internal.signV11({ method: "GET", url, ak: AK, sk: SK, sdkDateOverride: DT })
  const oracle = oV11(AK, SK, new URL(url).host, "/v1/subscription", "GET", "", null, DT)
  assert.equal(mine.Authorization, oracle.Authorization)
  assert.match(mine.Authorization, /^V11-HMAC-SHA256 Credential=AKTEST\/20261101\/cn-southwest-2\/apic, SignedHeaders=host;x-sdk-date, Signature=[0-9a-f]{64}$/)
  assert.equal(mine["Content-Type"], undefined, "GET 不能带 content-type（APIG.0301）")
})

test("signV11 POST claim 带 content-type，body 影响签名", () => {
  const url = "https://modelgw-0004.officeace.cn-southwest-2.huaweicloud-agentarts.com/v1/subscription/bonus/claim"
  const a = _internal.signV11({ method: "POST", url, ak: AK, sk: SK, bodyText: "", contentType: "application/json;charset=utf8", sdkDateOverride: DT })
  const b = _internal.signV11({ method: "POST", url, ak: AK, sk: SK, bodyText: "{}", contentType: "application/json;charset=utf8", sdkDateOverride: DT })
  const oracle = oV11(AK, SK, new URL(url).host, "/v1/subscription/bonus/claim", "POST", "", "application/json;charset=utf8", DT)
  assert.equal(a.Authorization, oracle.Authorization)
  assert.notEqual(a.Authorization, b.Authorization, "不同 body 必须不同签名")
  assert.equal(a["Content-Type"], "application/json;charset=utf8")
})

test("V11 派生 key 的 hex 串怪癖：与「把 hex 当原始字节」不同", () => {
  // 同样的 step1/seed，但把 signingKey 当原始 32 字节（而非 hex 串）算签名，结果必须不同
  const url = "https://gw.example/v1/subscription"
  const step1 = createHmac("sha256", AK).update(SK, "utf8").digest()
  const scope = "20261101/cn-southwest-2/apic"
  const seed = Buffer.concat([Buffer.from(scope, "utf8"), Buffer.from([1])])
  const signingKeyRaw = createHmac("sha256", step1).update(seed).digest().subarray(0, 32)
  const sts = ["V11-HMAC-SHA256", DT, scope, oSha(["GET", "/v1/subscription/", "", `host:gw.example\nx-sdk-date:${DT}\n`, "host;x-sdk-date", oSha("")].join("\n"))].join("\n")
  const sigRaw = createHmac("sha256", signingKeyRaw).update(sts, "utf8").digest("hex")
  const mine = _internal.signV11({ method: "GET", url, ak: AK, sk: SK, sdkDateOverride: DT })
  assert.ok(!new RegExp(sigRaw).test(mine.Authorization), "插件用的是 hex 串当 key，不能等于原始字节当 key 的结果")
})

// ---- fitBody / aggregated / explained ----

test("fitBody: 强制流、补 include_usage、glm-5.3 去 thinking、max_tokens+1024、钳位", () => {
  const fit = _internal.fitBody(JSON.stringify({ model: "deepseek-v4-pro", messages: [], max_tokens: 100, temperature: 5, top_p: 2, stream: false }))
  const b = JSON.parse(fit.body)
  assert.equal(b.stream, true)
  assert.deepEqual(b.stream_options, { include_usage: true })
  assert.equal(b.max_tokens, 1124)
  assert.equal(b.temperature, 2)
  assert.equal(b.top_p, 1)
  assert.equal(fit.wanted, false)

  const glm = _internal.fitBody(JSON.stringify({ model: "glm-5.3", messages: [], thinking: true, reasoning_effort: "high", max_tokens: 8 }))
  const gb = JSON.parse(glm.body)
  assert.equal(gb.thinking, undefined)
  assert.equal(gb.reasoning_effort, undefined)
  assert.deepEqual(gb.stream_options, { include_usage: true }, "glm-5.3 去掉原始 stream_options 后仍补回 include_usage")
  assert.equal(gb.max_tokens, 8, "小于 16 的 max_tokens 不加余量")
})

test("aggregated: SSE 折叠成单个 chat.completion", async () => {
  const sse = [
    'data: {"id":"x","created":1,"model":"m","choices":[{"delta":{"content":"你好"}}]}',
    'data: {"id":"x","choices":[{"delta":{"reasoning_content":"思考"}}]}',
    'data: {"id":"x","choices":[{"delta":{"content":"世界"},"finish_reason":"stop"}],"usage":{"prompt_tokens":2,"completion_tokens":4,"total_tokens":6}}',
    "data: [DONE]",
  ].join("\n")
  const res = new Response(sse, { status: 200, headers: { "content-type": "text/event-stream" } })
  const out = await _internal.aggregated(res, "fallback")
  const j = await out.json()
  assert.equal(j.object, "chat.completion")
  assert.equal(j.choices[0].message.content, "你好世界")
  assert.equal(j.choices[0].message.reasoning_content, "思考")
  assert.equal(j.choices[0].finish_reason, "stop")
  assert.equal(j.usage.total_tokens, 6)
  assert.match(out.headers.get("content-type"), /application\/json/)
})

test("explained: 积分耗尽改写为 insufficient_quota + kept；普通 400 透传 + kept", async () => {
  const exhausted = new Response('{"error":{"message":"insufficient points"}}', { status: 400, headers: {} })
  const e = await _internal.explained(exhausted)
  assert.equal(e.headers.get("X-Magpie-Sign-In"), "kept")
  const ej = await e.json()
  assert.equal(ej.error.type, "insufficient_quota")
  assert.match(ej.error.message, /insufficient points/)

  const plain = new Response('{"error":{"message":"bad request"}}', { status: 400, headers: {} })
  const p = await _internal.explained(plain)
  assert.equal(p.headers.get("X-Magpie-Sign-In"), "kept")
  assert.equal((await p.text()).includes("bad request"), true)
})

// ---- usageOf ----

test("usageOf: 每桶一行明细 + 聚合门控窗口；过期桶折叠为文案", () => {
  const now = Date.parse("2026-11-01T00:00:00Z")
  const sub = {
    skus: [{
      sku_name: "标准版", sku_code: "officeace.standard",
      expired_time: "2026-12-01T00:00:00Z",
      quotas: [
        { sku_attr_code: "officeace_points", sku_value: 10000, current_value: 2000, expired_time: "2026-12-01T00:00:00Z" },
        { sku_attr_code: "officeace_points", sku_value: 500, current_value: 0, expired_time: "2026-10-01T00:00:00Z" }, // 已过期
        { sku_attr_code: "other", sku_value: 999, current_value: 0 }, // 非积分
      ],
    }],
    bonus_skus: [
      { activity_id: "b1", points: 200, current_value: 50, expired_time: "2026-11-02T00:00:00Z" },
    ],
  }
  const u = _internal.usageOf(sub, now)
  assert.equal(u.plan, "标准版")

  // windows[0] 是唯一的门控窗口：聚合总量（10000 套餐 + 200 奖励，过期的 500 不计）
  const gate = u.windows[0]
  assert.equal(gate.name, "积分总额")
  assert.equal(gate.limit, 10200)
  assert.equal(gate.amount, 2050, "2000 + 50")
  assert.equal(gate.used, (100 * 2050) / 10200)
  assert.equal(gate.runsOut, 150, "最先到期的是 11-02 的奖励，剩 150")
  assert.match(gate.runsOutAt, /^2026-11-02T00:00:00/)
  assert.equal(gate.aside, undefined, "门控窗口不能 aside")

  // 其余全部 aside 明细，不参与门控
  const details = u.windows.slice(1)
  assert.equal(details.length, 3)
  assert.ok(details.every((d) => d.aside === true), "明细行必须 aside，单个用完的桶不能把账号判死")

  const pkg = details[0]
  assert.equal(pkg.name, "标准版 · 剩 8000")
  assert.equal(pkg.amount, 2000)
  assert.equal(pkg.limit, 10000)
  assert.equal(pkg.used, 20)
  assert.equal(pkg.resetsAt, "2026-12-01T00:00:00.000Z")

  const gone = details[1]
  assert.equal(gone.name, "标准版 · 剩 500")
  assert.equal(gone.display, "剩 0 / 500（已过期）")
  assert.equal(gone.amount, undefined, "过期桶不带 amount/limit，否则读起来像全剩")
  assert.equal(gone.limit, undefined)
  assert.equal(gone.used, undefined)
  assert.equal(gone.resetsAt, "2026-10-01T00:00:00.000Z")

  const bonus = details[2]
  assert.equal(bonus.name, "活动奖励 · 剩 150")
  assert.equal(bonus.amount, 50)
  assert.equal(bonus.limit, 200)
  assert.equal(bonus.used, 25)
  assert.equal(bonus.resetsAt, "2026-11-02T00:00:00.000Z")

  assert.match(u.until, /^2026-12-01/) // 套餐到期
})

test("usageOf: trial 套餐无到期时间，不编造 resetsAt", () => {
  const now = Date.parse("2026-11-01T00:00:00Z")
  const sub = {
    skus: [{
      sku_name: "体验版", sku_code: "officeace.trial",
      quotas: [{ sku_attr_code: "officeace_points", sku_value: 500, current_value: 100 }],
    }],
    bonus_skus: [],
  }
  const u = _internal.usageOf(sub, now)
  assert.equal(u.windows.length, 2, "聚合 + 一行明细")
  assert.equal(u.windows[0].limit, 500)
  assert.equal(u.windows[0].runsOutAt, undefined, "无到期桶没有 runsOut")
  const pkg = u.windows[1]
  assert.equal(pkg.name, "体验版 · 剩 400")
  assert.equal(pkg.resetsAt, undefined, "trial 不编造到期时间")
  assert.equal(pkg.amount, 100)
  assert.equal(u.until, undefined, "trial 套餐没有 until")
})

// ---- mock 上游 ----

function setup() {
  return new Promise((resolve, reject) => {
    let handler = null
    const server = createServer((req, res) => {
      let raw = ""
      req.on("data", (c) => (raw += c))
      req.on("end", () => handler?.(req, res, raw))
    })
    server.listen(0, "127.0.0.1", () => {
      process.env.OFFICEACE_CLOUD_BASE = `http://127.0.0.1:${server.address().port}`
      import(`./index.mjs?ts=${Date.now()}`)
        .then((mod) => resolve({ server, mod, setHandler: (h) => { handler = h } }))
        .catch(reject)
    })
  })
}

const account = (port, extra = {}) => ({
  type: "api",
  key: "AKTEST",
  metadata: {
    sk: "SKTEST",
    appKey: "mk", appSecret: "ms",
    baseUrl: `http://127.0.0.1:${port}/v2`,
    ...extra,
  },
})

test("fetchPermission: CPV 解析 model key/secret 与网关地址", async () => {
  const { server, mod, setHandler } = await setup()
  setHandler((req, res) => {
    assert.equal(req.headers["x-subscription-type"], "v2")
    assert.match(req.headers.authorization, /^SDK-HMAC-SHA256 Access=AKTEST,/)
    res.writeHead(200, { "Content-Type": "application/json" })
    res.end(JSON.stringify({
      account_id: "acc-1",
      model_info: {
        model_api_url_base: "https://modelgw-0004.officeace.cn-southwest-2.huaweicloud-agentarts.com",
        model_auth_info: { model_app_key: "mk", model_app_secret: "ms" },
      },
    }))
  })
  const info = await mod._internal.fetchPermission("AKTEST", "SKTEST")
  assert.equal(info.appKey, "mk")
  assert.equal(info.appSecret, "ms")
  assert.equal(info.baseUrl, "https://modelgw-0004.officeace.cn-southwest-2.huaweicloud-agentarts.com/v2")
  assert.equal(info.accountId, "acc-1")
  server.close()
})

test("authorize: 成功存 metadata；坏密钥回 failed", async () => {
  const { server, mod, setHandler } = await setup()
  const plugin = await mod.OfficeAceAkskPlugin()
  const method = plugin.auth.methods[0]
  assert.equal(method.type, "api")
  assert.deepEqual(method.prompts.map((p) => p.key), ["ak", "sk"])

  // 空 AK/SK
  assert.equal((await method.authorize({})).type, "failed")

  // CPV 401
  setHandler((req, res) => { res.writeHead(401, { "Content-Type": "application/json" }); res.end('{"error_code":"APIG.0301","error_msg":"AK/SK wrong"}') })
  const bad = await method.authorize({ ak: "AKTEST", sk: "SKTEST" })
  assert.equal(bad.type, "failed")
  assert.match(bad.error, /权限校验失败/)

  // CPV 成功
  setHandler((req, res) => {
    res.writeHead(200, { "Content-Type": "application/json" })
    res.end(JSON.stringify({ account_id: "acc-1", model_info: { model_api_url_base: "modelgw-1.example.com", model_auth_info: { model_app_key: "mk", model_app_secret: "ms" } } }))
  })
  const ok = await method.authorize({ ak: "AKTEST", sk: "SKTEST" })
  assert.equal(ok.type, "success")
  assert.equal(ok.key, "AKTEST")
  assert.equal(ok.metadata.sk, "SKTEST")
  assert.equal(ok.metadata.appKey, "mk")
  assert.equal(ok.metadata.appSecret, "ms")
  assert.equal(ok.metadata.baseUrl, "https://modelgw-1.example.com/v2")
  server.close()
})

test("loader fetch: Basic 头注入、非流式聚合、400 改写", async () => {
  const { server, mod, setHandler } = await setup()
  const plugin = await mod.OfficeAceAkskPlugin()
  const auth = account(server.address().port)
  const loader = await plugin.auth.loader(async () => auth)
  assert.equal(loader.baseURL, `http://127.0.0.1:${server.address().port}/v2`)

  // 非流式请求 → 网关回 SSE → 聚合成 chat.completion
  setHandler((req, res, raw) => {
    assert.equal(req.headers.authorization, "Basic " + Buffer.from("mk:ms").toString("base64"))
    assert.equal(req.headers["user-agent"], "OfficeAce/1.0")
    const body = JSON.parse(raw)
    assert.equal(body.stream, true, "fitBody 强制流")
    assert.deepEqual(body.stream_options, { include_usage: true })
    res.writeHead(200, { "Content-Type": "text/event-stream" })
    res.end('data: {"id":"x","model":"m","choices":[{"delta":{"content":"hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}\ndata: [DONE]\n')
  })
  const res = await loader.fetch(`http://127.0.0.1:${server.address().port}/v2/chat/completions`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ model: "deepseek-v4-pro", messages: [{ role: "user", content: "hi" }] }),
  })
  assert.equal(res.status, 200)
  const j = await res.json()
  assert.equal(j.object, "chat.completion")
  assert.equal(j.choices[0].message.content, "hi")

  // 流式请求 → 透传
  setHandler((req, res) => { res.writeHead(200, { "Content-Type": "text/event-stream" }); res.end("data: {\"choices\":[{\"delta\":{\"content\":\"s\"}}]}\ndata: [DONE]\n") })
  const sres = await loader.fetch(`http://127.0.0.1:${server.address().port}/v2/chat/completions`, {
    method: "POST", body: JSON.stringify({ model: "m", stream: true, messages: [] }),
  })
  assert.match(sres.headers.get("content-type") ?? "", /text\/event-stream/)

  // 400 积分耗尽 → insufficient_quota
  setHandler((req, res) => { res.writeHead(400, { "Content-Type": "application/json" }); res.end('{"error":{"message":"insufficient points"}}') })
  const eres = await loader.fetch(`http://127.0.0.1:${server.address().port}/v2/chat/completions`, { method: "POST", body: "{}" })
  assert.equal(eres.status, 400)
  assert.equal(eres.headers.get("X-Magpie-Sign-In"), "kept")
  assert.equal((await eres.json()).error.type, "insufficient_quota")
  server.close()
})

test("usage: 订阅查询汇总积分；401/错误带 signIn:kept", async () => {
  const { server, mod, setHandler } = await setup()
  const plugin = await mod.OfficeAceAkskPlugin()
  const auth = account(server.address().port)
  setHandler((req, res) => {
    assert.match(req.headers.authorization, /^V11-HMAC-SHA256 Credential=AKTEST\//)
    res.writeHead(200, { "Content-Type": "application/json" })
    res.end(JSON.stringify({
      skus: [{ sku_name: "标准版", sku_code: "officeace.standard", expired_time: "2099-01-01T00:00:00Z",
        quotas: [{ sku_attr_code: "officeace_points", sku_value: 5000, current_value: 1000, expired_time: "2099-01-01T00:00:00Z" }] }],
      bonus_skus: [],
    }))
  })
  const usage = await plugin.auth.usage(async () => auth)
  assert.equal(usage.plan, "标准版")
  assert.equal(usage.windows[0].name, "积分总额")
  assert.equal(usage.windows[0].limit, 5000)
  assert.equal(usage.windows[0].amount, 1000)
  assert.equal(usage.windows.length, 2, "聚合门控 + 一行明细")
  assert.equal(usage.windows[1].aside, true)
  assert.equal(usage.signIn, "kept")

  setHandler((req, res) => { res.writeHead(401, { "Content-Type": "application/json" }); res.end('{"error_code":"APIG.0301"}') })
  const dead = await plugin.auth.usage(async () => auth)
  assert.equal(dead.signIn, "kept")
  assert.match(dead.error, /401/)
  server.close()
})

test("checkin: before/after 差额上报 claimed；无可领 done", async () => {
  const { server, mod, setHandler } = await setup()
  const plugin = await mod.OfficeAceAkskPlugin()
  const auth = account(server.address().port)
  const before = { bonus_skus: [{ activity_id: "daily", points: 100, current_value: 0, expired_time: "2099-01-01T00:00:00Z" }] }
  const after = { bonus_skus: [{ activity_id: "daily", points: 100, current_value: 0, expired_time: "2099-01-01T00:00:00Z" }, { activity_id: "newcomer", points: 500, current_value: 0, expired_time: "2099-01-01T00:00:00Z" }] }
  let calls = 0
  setHandler((req, res) => {
    calls++
    if (req.method === "POST") {
      assert.ok(req.url.includes("/bonus/claim"))
      assert.equal(req.headers["content-type"], "application/json;charset=utf8")
      res.writeHead(200, { "Content-Type": "application/json" }); res.end("{}")
    } else {
      res.writeHead(200, { "Content-Type": "application/json" })
      res.end(JSON.stringify(calls <= 1 ? before : after))
    }
  })
  const r = await plugin.auth.checkin(async () => auth)
  assert.equal(r.outcome, "claimed")
  assert.equal(r.credit, 500, "新增 newcomer 500")
  assert.match(r.message, /500/)

  // 已无可领：before == after
  setHandler((req, res) => {
    if (req.method === "POST") { res.writeHead(200, { "Content-Type": "application/json" }); res.end("{}") }
    else { res.writeHead(200, { "Content-Type": "application/json" }); res.end(JSON.stringify(before)) }
  })
  const r2 = await plugin.auth.checkin(async () => auth)
  assert.equal(r2.outcome, "done")
  server.close()
})

test("provider.models: 拉取上游；无 Basic 回退静态；config 声明供应商", async () => {
  const { server, mod, setHandler } = await setup()
  const plugin = await mod.OfficeAceAkskPlugin()
  const auth = account(server.address().port)
  setHandler((req, res) => {
    assert.equal(req.headers.authorization, "Basic " + Buffer.from("mk:ms").toString("base64"))
    res.writeHead(200, { "Content-Type": "application/json" })
    res.end(JSON.stringify({ data: ["deepseek-v4-pro", { id: "custom-x", name: "Custom X" }] }))
  })
  const models = await plugin.provider.models({ id: "officeace-aksk", models: {} }, { auth })
  assert.equal(models["deepseek-v4-pro"].name, "DeepSeek-V4-Pro")
  assert.equal(models["custom-x"].name, "Custom X")
  assert.equal(models["deepseek-v4-pro"].capabilities.toolcall, true)

  const fallback = await plugin.provider.models(
    { id: "officeace-aksk", models: _internal.staticModels() }, // magpie 里 config hook 已放入静态清单
    { auth: { type: "api", key: "", metadata: {} } },
  )
  assert.ok(fallback["glm-5.3"], "无 Basic 时原样回退 config 里的静态清单")

  // config hook
  const cfg = {}
  await plugin.config(cfg)
  assert.equal(cfg.provider["officeace-aksk"].name, "OfficeAce (AK/SK)")
  assert.equal(cfg.provider["officeace-aksk"].npm, "@ai-sdk/openai-compatible")
  assert.ok(cfg.provider["officeace-aksk"].models["kimi-k2.6"])
  server.close()
})

test("fitBody: 始终思考的模型（glm-5.3-flash）剥离关思考参数", () => {
  // 客户端要求不思考：enable_thinking:false + reasoning_effort:none 全部去掉
  const fit = _internal.fitBody(JSON.stringify({ model: "glm-5.3-flash", messages: [], enable_thinking: false, reasoning_effort: "none", stream: true }))
  const b = JSON.parse(fit.body)
  assert.equal(b.enable_thinking, undefined, "enable_thinking:false 触发 ModelArts.81001，必须去掉")
  assert.equal(b.reasoning_effort, undefined, "none 对始终思考的模型无效")
  assert.equal(b.stream, true)

  // magpie 映射后的 low 保留（用户配置的思考等级不丢）
  const fit2 = _internal.fitBody(JSON.stringify({ model: "glm-5.3-flash", messages: [], enable_thinking: false, reasoning_effort: "low", stream: true }))
  const b2 = JSON.parse(fit2.body)
  assert.equal(b2.enable_thinking, undefined)
  assert.equal(b2.reasoning_effort, "low")

  // 其他模型不受影响
  const fit3 = _internal.fitBody(JSON.stringify({ model: "deepseek-v4-pro", messages: [], enable_thinking: false, reasoning_effort: "none", stream: true }))
  const b3 = JSON.parse(fit3.body)
  assert.equal(b3.enable_thinking, false)
  assert.equal(b3.reasoning_effort, "none")
})

test("gatewayFetch: ModelArts.81001 去思考参数重发一次（兜底清单外模型）", async () => {
  const { server, mod, setHandler } = await setup()
  const plugin = await mod.OfficeAceAkskPlugin()
  const auth = account(server.address().port)
  const loader = await plugin.auth.loader(async () => auth)
  const url = `http://127.0.0.1:${server.address().port}/v2/chat/completions`
  const bodies = []
  setHandler((req, res, raw) => {
    bodies.push(JSON.parse(raw))
    if (bodies.length === 1) {
      res.writeHead(400, { "Content-Type": "application/json" })
      res.end('{"error":{"code":"ModelArts.81001","message":"该模型始终思考，不支持关闭思考；请使用 low、high 或 max。"}}')
      return
    }
    res.writeHead(200, { "Content-Type": "text/event-stream" })
    res.end('data: {"id":"x","model":"m","choices":[{"delta":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}\ndata: [DONE]\n')
  })
  const res = await loader.fetch(url, {
    method: "POST",
    body: JSON.stringify({ model: "unknown-always-thinking", messages: [], enable_thinking: false, reasoning_effort: "low", stream: true }),
  })
  assert.equal(res.status, 200, "重发后成功")
  assert.equal(bodies.length, 2)
  assert.equal(bodies[0].enable_thinking, false)
  assert.equal(bodies[1].enable_thinking, undefined, "重发时去掉思考参数")
  assert.equal(bodies[1].reasoning_effort, undefined)
  server.close()
})

test("fitBody: max_tokens 钳到网关上限 131072（Qoder 发 1048576 会 400）", () => {
  // 实测：max_tokens 1048576(+1024) 超过 glm-5.3-flash 的上限 [1,131072] →
  // 400 ModelArts.81001「max_tokens参数非法」
  const fit = _internal.fitBody(JSON.stringify({ model: "glm-5.3-flash", messages: [], max_tokens: 1048576, stream: true }))
  assert.equal(JSON.parse(fit.body).max_tokens, 131072, "超限的预算钳到上限（含思考余量后仍不超）")

  const fit2 = _internal.fitBody(JSON.stringify({ model: "deepseek-v4-pro", messages: [], max_tokens: 100000, stream: true }))
  assert.equal(JSON.parse(fit2.body).max_tokens, 101024, "限内的预算照常 +1024")

  const fit3 = _internal.fitBody(JSON.stringify({ model: "m", messages: [], max_tokens: 8, stream: true }))
  assert.equal(JSON.parse(fit3.body).max_tokens, 8, "小于 16 的显式预算不动")
})

test("gatewayFetch: max_tokens 超限按正文里的真实上限重发一次", async () => {
  const { server, mod, setHandler } = await setup()
  const plugin = await mod.OfficeAceAkskPlugin()
  const auth = account(server.address().port)
  const loader = await plugin.auth.loader(async () => auth)
  const url = `http://127.0.0.1:${server.address().port}/v2/chat/completions`
  const bodies = []
  setHandler((req, res, raw) => {
    bodies.push(JSON.parse(raw))
    if (bodies.length === 1) {
      res.writeHead(400, { "Content-Type": "application/json" })
      res.end('{"error":{"code":"ModelArts.81001","message":"max_tokens参数非法：限制数值范围[1,65536]"}}')
      return
    }
    res.writeHead(200, { "Content-Type": "text/event-stream" })
    res.end('data: {"id":"x","model":"m","choices":[{"delta":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}\ndata: [DONE]\n')
  })
  const res = await loader.fetch(url, {
    method: "POST",
    body: JSON.stringify({ model: "small-cap-model", messages: [], max_tokens: 131072, stream: true }),
  })
  assert.equal(res.status, 200, "按正文上限重发后成功")
  assert.equal(bodies.length, 2)
  assert.equal(bodies[0].max_tokens, 131072)
  assert.equal(bodies[1].max_tokens, 65536, "重发时用正文给出的真实上限")
  server.close()
})
