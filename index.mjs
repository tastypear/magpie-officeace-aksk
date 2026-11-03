// OpenCode provider plugin for OfficeAce (Huawei Cloud AgentArts model
// gateway), signed in with a **permanent AK/SK** — no browser OAuth, no
// temporary credentials, nothing to renew. The account keeps working until
// the keys themselves are revoked.
//
// The two-level authentication is the one tastypear/credgate runs in
// production (a multi-account gateway for the same provider):
//
//   control plane  agentarts.<region>.myhuaweicloud.com
//                  /v1/claw/client-permission-validate
//                  → SDK-HMAC-SHA256, signed with the permanent AK/SK
//                  → answers the model app key/secret and the gateway host
//   gateway        modelgw-*.huaweicloud-agentarts.com
//                  /v1/subscription, /v1/subscription/bonus/claim
//                  → V11-HMAC-SHA256, signing key derived through the
//                    region scope (HMAC(HMAC(AK, SK), scope + 0x01) as hex)
//   inference      /v2/chat/completions, /v2/models
//                  → Basic base64(model_app_key:model_app_secret)
//
// The protocol's response shapes follow theseaiying/magpie-officeace-plugin
// (the OAuth variant of this plugin) and Q-shuang-dot/officeace2api; the
// signing and the credit arithmetic follow credgate. Chats are OpenAI's
// shape at the account's own gateway; the gateway answers streamed bodies
// best, so one asked for as one piece is folded back together below.

// provider id is officeace-aksk (not officeace) so this plugin can sit beside
// theseaiying's OAuth variant of the same provider without an id clash.

import { createHmac, createHash, randomBytes } from "node:crypto"

const PROVIDER = "officeace-aksk"
const NPM = "@ai-sdk/openai-compatible"

// The AgentArts control plane and the paths this plugin asks. The region can
// be overridden for tests (OFFICEACE_CLOUD_BASE) — production is fixed.
const CLOUD_BASE = (process.env.OFFICEACE_CLOUD_BASE || "https://agentarts.cn-southwest-2.myhuaweicloud.com").replace(/\/+$/, "")
const REGION = "cn-southwest-2"
const SCOPE_SERVICE = "apic" // APIG's service name in the V11 credential scope
const CPV_PATH = "/v1/claw/client-permission-validate"
const SUB_PATH = "/v1/subscription"
const CLAIM_PATH = "/v1/subscription/bonus/claim"

// The default gateway, where chats and the model list go when an account's
// permission check named none. A sign-in always carries its own.
const DEFAULT_GATEWAY = "https://modelgw-0004.officeace.cn-southwest-2.huaweicloud-agentarts.com"
const UA = "OfficeAce/1.0"

// [id, name, context, efforts] — the models the gateway is known to serve,
// as officeace2api's registry reads them; the account's own list comes from
// the gateway's /models when it answers. glm-5.3 takes no thinking param
// (officeace2api strips it), so it gets no reasoning levels here either.
const MODELS = [
  ["deepseek-v4.1-flash", "DeepSeek-V4.1-Flash", 1000000, ["high"]],
  ["deepseek-v4-flash", "DeepSeek-V4-Flash", 1000000],
  ["deepseek-v4-pro", "DeepSeek-V4-Pro", 1000000, ["high"]],
  ["deepseek-v4-flash-0731", "DeepSeek-V4-Flash-0731", 1000000],
  ["deepseek-v3.2", "DeepSeek-V3.2", 128000, ["high"]],
  ["deepseek-r1-250528", "DeepSeek-R1-250528", 128000, ["high"]],
  ["glm-5.3", "GLM-5.3", 198000],
  ["glm-5.2", "GLM-5.2", 198000, ["high"]],
  ["glm-5.1", "GLM-5.1", 198000, ["high"]],
  ["kimi-k2.6", "Kimi-K2.6", 256000],
  ["qwen3-32b", "Qwen3-32B", 128000],
  ["qwen3-30b-a3b", "Qwen3-30B-A3B", 128000],
  ["openpangu-2.0-pro", "openPangu-2.0-Pro", 128000],
  ["openpangu-2.0-flash", "openPangu-2.0-Flash", 128000],
]

// ---- the account's gateway --------------------------------------------------
// The stored account is magpie's api shape: { type: "api", key: <AK>,
// metadata: { sk, appKey, appSecret, baseUrl, accountId } }. The AK/SK sign
// the control plane; the model key/secret the permission check gave sign the
// chats, as a Basic key that does not expire.

function baseUrlOf(auth) {
  const base = String(auth?.metadata?.baseUrl || "").replace(/\/+$/, "")
  return base || DEFAULT_GATEWAY + "/v2"
}

// hostOf is the gateway host the subscription API answers at: the base
// without its /v2 (or whatever version) tail.
function hostOf(auth) {
  return baseUrlOf(auth).replace(/\/v\d+\/?$/, "")
}

// basicOf is the Authorization an account signs chats with.
function basicOf(auth) {
  const md = auth?.metadata ?? {}
  if (md.appKey && md.appSecret) return "Basic " + Buffer.from(`${md.appKey}:${md.appSecret}`).toString("base64")
  return ""
}

// credentialOf is what the two signatures sign with: the permanent pair.
function credentialOf(auth) {
  return { accessKey: String(auth?.key || ""), secretKey: String(auth?.metadata?.sk || "") }
}

// ---- Huawei Cloud's signatures ----------------------------------------------
// (as credgate's signing.py makes them, matching officeace2api's signer: the
// control plane signs SDK-HMAC-SHA256, the subscription API V11-HMAC-SHA256,
// whose key is derived through the region scope. A permanent AK/SK carries no
// security token and no project id, so none is signed or sent.)

const sha256Hex = (s) => createHash("sha256").update(s, "utf8").digest("hex")
const hmacHex = (key, data) => createHmac("sha256", key).update(data, "utf8").digest("hex")
const rfc3986 = (s) => encodeURIComponent(s).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`)

function sdkDate() {
  return new Date().toISOString().replace(/[:-]|\.\d{3}/g, "")
}

function canonicalUri(url) {
  let p = url.pathname.split("/").map((seg) => rfc3986(decodeURIComponent(seg))).join("/")
  if (!p.endsWith("/")) p += "/"
  return p
}

function canonicalQuery(url) {
  const pairs = []
  url.searchParams.forEach((v, k) => pairs.push([k, v]))
  pairs.sort(([a, b], [c, d]) => (a === c ? b.localeCompare(d) : a.localeCompare(c)))
  return pairs.map(([k, v]) => `${rfc3986(k)}=${rfc3986(v)}`).join("&")
}

function signedHeaders(headers) {
  const norm = {}
  for (const [k, v] of Object.entries(headers)) norm[k.toLowerCase()] = String(v).trim().replace(/\s+/g, " ")
  const names = Object.keys(norm).sort()
  return { norm, names }
}

function canonicalRequest(method, url, norm, names, payloadHash) {
  const head = names.map((n) => `${n}:${norm[n]}`).join("\n") + "\n"
  return [method.toUpperCase(), canonicalUri(url), canonicalQuery(url), head, names.join(";"), payloadHash].join("\n")
}

// signSdk is the control plane's SDK-HMAC-SHA256: the SK is the key itself.
function signSdk({ method, url, ak, sk, bodyText = "", headers = {}, sdkDateOverride }) {
  const out = { ...headers }
  out.Host = new URL(url).host
  out["X-Sdk-Date"] = sdkDateOverride || sdkDate()
  const { norm, names } = signedHeaders(out)
  const cr = canonicalRequest(method, new URL(url), norm, names, sha256Hex(bodyText))
  const sts = ["SDK-HMAC-SHA256", norm["x-sdk-date"], sha256Hex(cr)].join("\n")
  out.Authorization = `SDK-HMAC-SHA256 Access=${ak}, SignedHeaders=${names.join(";")}, Signature=${hmacHex(sk, sts)}`
  return out
}

// signV11 is the subscription API's V11-HMAC-SHA256: the signing key is
// HMAC(HMAC(AK, SK), scope + 0x01)[0..32] as its **hex string** — Huawei's
// own derivation, the hex characters fed as the key's bytes, not the raw 32.
// A GET names no content-type (the gateway answers APIG.0301 to one).
function signV11({ method, url, ak, sk, bodyText = "", headers = {}, contentType, sdkDateOverride }) {
  const out = { ...headers }
  out.Host = new URL(url).host
  out["X-Sdk-Date"] = sdkDateOverride || sdkDate()
  if (contentType) out["Content-Type"] = contentType
  const { norm, names } = signedHeaders(out)
  const date = norm["x-sdk-date"]
  const scope = `${date.slice(0, 8)}/${REGION}/${SCOPE_SERVICE}`
  const cr = canonicalRequest(method, new URL(url), norm, names, sha256Hex(bodyText))
  const sts = ["V11-HMAC-SHA256", date, scope, sha256Hex(cr)].join("\n")
  const step1 = createHmac("sha256", ak).update(sk, "utf8").digest()
  const seed = Buffer.concat([Buffer.from(scope, "utf8"), Buffer.from([1])])
  const signingKey = createHmac("sha256", step1).update(seed).digest().subarray(0, 32).toString("hex")
  out.Authorization = `V11-HMAC-SHA256 Credential=${ak}/${scope}, SignedHeaders=${names.join(";")}, Signature=${hmacHex(signingKey, sts)}`
  return out
}

// ---- the control plane -------------------------------------------------------

// fetchPermission asks which gateway and Basic key the account may use, with
// the permanent AK/SK doing the signing — the step the OAuth variant needs a
// browser for.
async function fetchPermission(ak, sk) {
  const url = `${CLOUD_BASE}${CPV_PATH}`
  const headers = signSdk({ method: "GET", url, ak, sk, headers: { "x-subscription-type": "v2" } })
  const res = await fetch(url, { headers, signal: AbortSignal.timeout(20000) })
  const text = await res.text()
  let json = null
  try {
    json = JSON.parse(text)
  } catch {}
  if (!res.ok) {
    throw new Error(`OfficeAce 权限校验失败：${json?.error_msg || json?.error_code || `HTTP ${res.status}`}`)
  }
  if (json?.error_code) {
    throw new Error(`OfficeAce 权限校验失败：${json.error_code}${json?.error_msg ? `: ${json.error_msg}` : ""}`)
  }
  const mi = json?.model_info || json?.subscription?.model_info || json?.modelInfo || null
  const host = String(mi?.model_api_url_base || "").replace(/^https?:\/\//, "").replace(/\/+$/, "")
  return {
    accountId: String(json?.account_id || ""),
    appKey: String(mi?.model_auth_info?.model_app_key || ""),
    appSecret: String(mi?.model_auth_info?.model_app_secret || ""),
    baseUrl: host ? `https://${host}/v2` : "",
  }
}

// controlCall asks the subscription API at the account's gateway host,
// V11-signed with the permanent AK/SK.
async function controlCall(auth, method, path, bodyText) {
  const { accessKey, secretKey } = credentialOf(auth)
  const url = hostOf(auth) + path
  const hasBody = bodyText !== undefined
  const headers = signV11({
    method,
    url,
    ak: accessKey,
    sk: secretKey,
    bodyText: hasBody ? bodyText : "",
    ...(hasBody ? { contentType: "application/json;charset=utf8" } : {}),
  })
  const res = await fetch(url, {
    method,
    headers,
    ...(hasBody ? { body: bodyText } : {}),
    signal: AbortSignal.timeout(20000),
  })
  const text = await res.text()
  let json = null
  try {
    json = JSON.parse(text)
  } catch {}
  return { status: res.status, ok: res.ok, json, text }
}

function subscriptionOf(auth) {
  return controlCall(auth, "GET", SUB_PATH)
}

// claimBonus presses the subscription card's one claim: the day's sign-in
// reward and any one-time newcomer gift, in one idempotent POST that answers
// the updated subscription. Its body is the empty string the client sends.
function claimBonus(auth) {
  return controlCall(auth, "POST", CLAIM_PATH, "")
}

// vendorError is the refusal the subscription or claim answer carries.
function vendorError(json) {
  if (!json || typeof json !== "object") return ""
  if (json.error_code) {
    const msg = json.error_msg || json.message || ""
    return `${json.error_code}${msg ? `: ${msg}` : ""}`
  }
  const code = Number.parseInt(json.code, 10)
  if (Number.isFinite(code) && code !== 0) {
    const msg = json.message || json.error_msg || ""
    return `${code}${msg ? `: ${msg}` : ""}`
  }
  return ""
}

// redacted keeps a vendor message from echoing a credential into the
// check-in result magpie keeps.
function redacted(auth, text) {
  let out = String(text ?? "")
  for (const secret of [auth?.key, auth?.metadata?.sk, auth?.metadata?.appSecret]) {
    if (typeof secret === "string" && secret) out = out.split(secret).join("[redacted]")
  }
  return out.length > 200 ? out.slice(0, 197) + "..." : out
}

// baselineOf is a subscription answer usable as a balance: its bonus list,
// no vendor error, and an object rather than an error page. Anything else
// would make every bonus look new.
function baselineOf(res) {
  const json = res?.json
  return res?.ok && json && typeof json === "object" && !Array.isArray(json)
    && !vendorError(json) && Array.isArray(json.bonus_skus) ? json : null
}

function bonusList(sub) {
  const items = Array.isArray(sub?.bonus_skus) ? sub.bonus_skus : []
  const out = []
  for (const item of items) {
    if (!item || typeof item !== "object") continue
    const key = String(item.activity_id ?? item.cbc_resource_id ?? item.activity_name ?? "").trim()
    if (!key) continue
    out.push({ key, total: Number(item.points) || 0, used: Number(item.current_value) || 0 })
  }
  return out
}

// gainedBetween counts what a claim added: each bonus's remaining amount
// grew by this much. One seen for the first time counts its remaining, not
// its whole grant, which may have come earlier.
function gainedBetween(before, after) {
  const previous = new Map()
  for (const b of bonusList(before)) previous.set(b.key, Math.max(0, b.total - b.used))
  let gained = 0
  for (const b of bonusList(after)) {
    const left = Math.max(0, b.total - b.used)
    gained += Math.max(0, left - (previous.get(b.key) ?? 0))
  }
  return gained
}

// ---- usage --------------------------------------------------------------------

const TIER_NAMES = { trial: "试用版", starter: "入门版", standard: "标准版", advanced: "高级版", premium: "尊享版", ultimate: "旗舰版" }

// usageOf turns a subscription answer into magpie's usage card. Two kinds of
// bucket — the plan's `skus[].quotas[]` (officeace_points) and the bonuses in
// `bonus_skus[]` — and the card shows each on its own, the way magpie's own
// codearts plugin does: one row per bucket, its remaining figure in the row's
// name, its own end time as resetsAt. Routing stays on ONE window over the
// whole balance: a bucket that ran dry (the day's check-in, say, spent before
// its evening end) must not tell magpie the account is out while the plan
// still has credits, so the detail rows are aside and only the total gates.
// An expired bucket is folded to text alone (aside, no amount/limit): with a
// count it would read as "all left" of a total that no longer exists. A
// `.trial` sku carries no expiry — shown as it is, never a date invented.
// An unlimited quota (-1) says no share, and is left out entirely.
function usageOf(sub, now = Date.now()) {
  const skus = Array.isArray(sub?.skus) ? sub.skus : []
  const bonus = Array.isArray(sub?.bonus_skus) ? sub.bonus_skus : []
  const round = (n) => Math.round(n * 100) / 100
  const num = (v) => (Number.isFinite(v) ? v : 0)
  const endMs = (s, never) => {
    if (never) return 0
    if (typeof s === "string" && s) {
      const t = Date.parse(s)
      if (Number.isFinite(t)) return t
    }
    return 0
  }
  let total = 0, used = 0
  const dying = []
  const details = []
  let plan = ""

  for (const s of skus) {
    const isTrial = String(s?.sku_code ?? "").endsWith(".trial")
    for (const q of Array.isArray(s?.quotas) ? s.quotas : []) {
      if (q?.sku_attr_code !== "officeace_points") continue
      const grant = Number(q.sku_value)
      if (!Number.isFinite(grant) || grant <= 0) continue
      const usedB = num(Number(q.current_value))
      if (!plan && typeof s.sku_name === "string") plan = s.sku_name
      const exp = endMs(q?.expired_time, isTrial)
      const expired = exp !== 0 && exp <= now
      const remaining = Math.max(0, grant - usedB)
      if (!expired) {
        total += grant
        used += usedB
        dying.push({ left: remaining, exp })
      }
      details.push({ name: `${s.sku_name ?? "套餐"} · 剩 ${round(remaining)}`, remaining, grant, usedB, expired,
        resetsAt: exp ? new Date(exp).toISOString() : "" })
    }
  }
  for (const b of bonus) {
    const grant = Number(b.points)
    if (!Number.isFinite(grant) || grant <= 0) continue
    const usedB = num(Number(b.current_value))
    const exp = endMs(b?.expired_time, false)
    const expired = exp !== 0 && exp <= now
    const remaining = Math.max(0, grant - usedB)
    if (!expired) {
      total += grant
      used += usedB
      dying.push({ left: remaining, exp })
    }
    details.push({ name: `${b.activity_name ?? "活动奖励"} · 剩 ${round(remaining)}`, remaining, grant, usedB, expired,
      resetsAt: exp ? new Date(exp).toISOString() : "" })
  }

  const windows = []
  // 路由只看这个聚合窗口：总余额归零才停用账号——按桶各自门控会让一个先用完的桶
  // （如每日签到当天扣完）把还有套餐积分的账号误判成耗尽。
  if (total > 0) {
    const w = {
      name: "积分总额",
      used: (100 * used) / total,
      display: `剩 ${round(total - used)} / ${round(total)}`,
      amount: used,
      limit: total,
      unit: "credits",
    }
    // the soonest moment credits left are lost, and how many — magpie's
    // smart routing spends the account whose credits expire first.
    let at = 0, amount = 0
    for (const d of dying) {
      if (!(d.left > 0) || d.exp <= now) continue
      if (!at || d.exp < at) { at = d.exp; amount = d.left }
      else if (d.exp === at) amount += d.left
    }
    if (at) Object.assign(w, { runsOutAt: new Date(at).toISOString(), runsOut: amount })
    windows.push(w)
  }
  // 每个桶一行：aside 纯展示不门控。过期的桶只留文案（不带 amount/limit，
  // 否则它的总量读起来像"全剩"）。
  for (const d of details) {
    const w = { name: d.name, unit: "credits", aside: true }
    if (d.resetsAt) w.resetsAt = d.resetsAt
    if (d.expired) {
      w.display = `剩 0 / ${round(d.grant)}（已过期）`
    } else {
      w.used = Math.min(100, Math.round((d.usedB / d.grant) * 100))
      w.amount = d.usedB
      w.limit = d.grant
      w.span = 0
    }
    windows.push(w)
  }
  const main = skus[0] || null
  const tier = String(main?.sku_code || "").split(".").pop() || ""
  const until = Date.parse(main?.expired_time || "") || 0
  return {
    plan: plan || main?.sku_name || TIER_NAMES[tier] || (total > 0 ? "OfficeAce" : ""),
    windows,
    ...(until ? { until: new Date(until).toISOString() } : {}),
  }
}

// ---- models ---------------------------------------------------------------------

const variants = (efforts) => Object.fromEntries((efforts ?? []).map((e) => [e, { reasoningEffort: e }]))

function staticModels() {
  return Object.fromEntries(
    MODELS.map(([id, name, context, efforts]) => [
      id,
      {
        name,
        limit: { context, output: 0 },
        tool_call: true,
        ...(efforts ? { reasoning: true, variants: variants(efforts) } : {}),
      },
    ]),
  )
}

function modelOf(provider, m) {
  const known = staticModels()[m.id]
  return {
    id: m.id,
    providerID: provider.id,
    name: m.name && m.name !== m.id ? m.name : known?.name || m.id,
    api: { id: m.id, url: baseUrlOf({ baseUrl: m.baseUrl }), npm: NPM },
    status: "active",
    headers: {},
    options: {},
    cost: { input: 0, output: 0, cache: { read: 0, write: 0 } },
    limit: { context: m.context ?? known?.limit?.context ?? 0, output: 0 },
    capabilities: {
      temperature: true,
      reasoning: !!known?.reasoning,
      attachment: false,
      toolcall: true,
      input: { text: true, image: false, audio: false, video: false, pdf: false },
      output: { text: true, image: false, audio: false, video: false, pdf: false },
      interleaved: false,
    },
    release_date: "",
    variants: known?.variants ?? {},
  }
}

// liveModels asks the account's own gateway for the models it serves.
async function liveModels(auth) {
  const url = baseUrlOf(auth) + "/models"
  const res = await fetch(url, {
    headers: { Accept: "application/json", Authorization: basicOf(auth), "User-Agent": UA },
    signal: AbortSignal.timeout(15000),
  })
  if (!res.ok) throw new Error(`the gateway's model list: HTTP ${res.status}`)
  const doc = await res.json().catch(() => ({}))
  const list = Array.isArray(doc?.data) ? doc.data : Array.isArray(doc) ? doc : []
  return list.map((m) => (typeof m === "string" ? { id: m } : m)).filter((m) => m?.id)
}

// ---- chat ------------------------------------------------------------------------

const NO_THINKING = new Set(["glm-5.3", "glm-5.3-test", "glm-5.3-zx", "glm-5-test"])
const STRIP_WHEN_NO_THINKING = ["thinking", "enable_thinking", "reasoning_effort", "stream_options"]

// The gateway counts max_tokens as the budget reasoning AND answer share
// (officeace2api's finding): a reasoning model spends it all thinking and
// answers with nothing. So the budget an agent gave is bumped by an
// allowance for the thinking; an explicit tiny one is passed as it is —
// an agent asking for 1 token means it.
const TINY_MAX_TOKENS = 16
const THINKING_ALLOWANCE = 1024

// fitBody mends a chat body the way officeace2api sends them: the thinking
// params glm-5.3 refuses are gone, the max_tokens budget is bumped, and the
// chat is asked for as a stream — the gateway answers those best, and one
// asked for as one piece is folded back together below. wanted says whether
// the agent asked for a stream; model, the model the chat names.
function fitBody(body) {
  if (typeof body !== "string") return { body, wanted: true, model: "" }
  let b
  try {
    b = JSON.parse(body)
  } catch {
    return { body, wanted: true, model: "" }
  }
  if (b === null || typeof b !== "object" || !Array.isArray(b.messages)) return { body, wanted: true, model: "" }
  const wanted = b.stream === true
  const model = String(b.model || "")
  if (NO_THINKING.has(model)) for (const k of STRIP_WHEN_NO_THINKING) delete b[k]
  const given = Number(b.max_tokens)
  if (Number.isFinite(given) && given >= TINY_MAX_TOKENS) b.max_tokens = given + THINKING_ALLOWANCE
  if (typeof b.temperature === "number") b.temperature = Math.min(2, Math.max(0, b.temperature))
  if (typeof b.top_p === "number") b.top_p = Math.min(1, Math.max(0, b.top_p))
  if (b.stream_options === undefined) b.stream_options = { include_usage: true }
  b.stream = true
  return { body: JSON.stringify(b), wanted, model }
}

// aggregated is a streamed answer folded into the one JSON body the agent
// asked for: every chunk's deltas accumulated, the usage the last chunk
// carries kept.
async function aggregated(res, fallbackModel) {
  const text = await res.text()
  const again = (body, type = "application/json") => {
    const headers = new Headers(res.headers)
    headers.set("content-type", type)
    headers.delete("content-length")
    headers.delete("content-encoding")
    return new Response(body, { status: res.status, statusText: res.statusText, headers })
  }
  if (!text.includes("data:")) return again(text)
  const acc = { id: "", created: 0, model: fallbackModel, content: "", reasoning: "", finish: null, usage: null, toolCalls: new Map() }
  for (let line of text.split("\n")) {
    line = line.trim()
    if (!line.startsWith("data:")) continue
    const data = line.slice(5).trim()
    if (!data || data === "[DONE]") continue
    let v
    try {
      v = JSON.parse(data)
    } catch {
      continue
    }
    if (v?.id && !acc.id) acc.id = v.id
    if (v?.created && !acc.created) acc.created = v.created
    if (v?.model) acc.model = v.model
    if (v?.usage) acc.usage = v.usage
    const at = v?.choices?.[0] ?? {}
    const d = at.delta ?? at.message ?? {}
    if (typeof d.content === "string") acc.content += d.content
    if (typeof d.reasoning_content === "string") acc.reasoning += d.reasoning_content
    for (const tc of Array.isArray(d.tool_calls) ? d.tool_calls : []) {
      const i = tc.index ?? 0
      const call = acc.toolCalls.get(i) || { id: "", type: "function", function: { name: "", arguments: "" } }
      if (tc.id) call.id = tc.id
      if (tc.type) call.type = tc.type
      // the name comes once, on the first piece; arguments gather
      if (tc.function?.name && !call.function.name) call.function.name = tc.function.name
      if (tc.function?.arguments) call.function.arguments += tc.function.arguments
      acc.toolCalls.set(i, call)
    }
    if (at.finish_reason) acc.finish = at.finish_reason
  }
  const message = { role: "assistant", content: acc.content }
  if (acc.reasoning) message.reasoning_content = acc.reasoning
  if (acc.toolCalls.size)
    message.tool_calls = [...acc.toolCalls.entries()].sort((x, y) => x[0] - y[0]).map(([, call]) => call)
  return again(JSON.stringify({
    id: acc.id || "chatcmpl-" + crypto.randomUUID(),
    object: "chat.completion",
    created: acc.created || Math.floor(Date.now() / 1000),
    model: acc.model || fallbackModel,
    choices: [{ index: 0, message, finish_reason: acc.finish || "stop", logprobs: null }],
    usage: acc.usage || { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 },
  }))
}

// EXHAUSTED_HINT says what the user can do about a chat refused for credits;
// an OfficeAce account holds packages, and one with none left is refused.
const EXHAUSTED_HINT = "this OfficeAce account's credits are spent; check the account's packages"
const EXHAUSTED = /insufficient (points?|quota|balance)|points? (exhausted|ran out)|积分(不足|已用尽)/i

// explained is a refused chat with the credits hint added to that refusal's
// message. It says the sign-in is kept on every refusal: a gateway 401 is
// about the Basic key, which never ends, and marking the account would only
// stop chats that a retry may pass.
async function explained(res) {
  const text = await res.text()
  const again = (body) => {
    const headers = new Headers(res.headers)
    headers.delete("content-length")
    headers.delete("content-encoding")
    headers.set("X-Magpie-Sign-In", "kept")
    return new Response(body, { status: res.status, statusText: res.statusText, headers })
  }
  if (!EXHAUSTED.test(text)) return again(text)
  let v
  try {
    v = JSON.parse(text)
  } catch {}
  const at = v?.error && typeof v.error === "object" ? v.error : v && typeof v === "object" ? v : null
  let msg = text.trim()
  if (typeof at?.message === "string") msg = at.message
  else if (typeof v?.error_msg === "string" && v.error_msg) msg = v.error_msg
  else if (typeof v?.msg === "string" && v.msg) msg = v.msg
  const headers = new Headers(res.headers)
  headers.set("content-type", "application/json")
  headers.delete("content-length")
  headers.delete("content-encoding")
  headers.set("X-Magpie-Sign-In", "kept")
  return new Response(JSON.stringify({ error: { message: `${msg} — ${EXHAUSTED_HINT}`, type: "insufficient_quota", code: null } }), {
    status: res.status,
    statusText: res.statusText,
    headers,
  })
}

// gatewayFetch is the fetch every chat of an account goes through: the
// account's Basic key on it, the body mended, a refusal explained, a stream
// folded back together for an agent that asked for one piece.
function gatewayFetch(auth) {
  return async (input, init) => {
    const req = input instanceof Request ? input : null
    const headers = new Headers(init?.headers ?? req?.headers)
    headers.delete("authorization")
    headers.delete("x-api-key")
    headers.delete("content-length")
    headers.set("Authorization", basicOf(auth))
    headers.set("User-Agent", UA)
    let body = init?.body
    if (body === undefined && req) body = await req.clone().text()
    const fit = fitBody(body)
    const res = await fetch(req ? req.url : input, { ...init, method: init?.method ?? req?.method, headers, body: fit.body })
    if (res.status >= 400) return explained(res)
    return fit.wanted ? res : aggregated(res, fit.model)
  }
}

// ---- CodeArts (码道)：第二个 provider，同一对永久 AK/SK -----------------------
// (provider id 为 codearts-aksk，社区的 OAuth 版占用 codearts。snap-access 的请求
//  同样是 SDK-HMAC-SHA256，但签名头比 agentarts 多一个 x-sdk-content-sha256；
//  聊天不换 Basic key，AK/SK 直接签。套餐分两种口径，statistics 的
//  package.is_token_package / is_credit_package 是官方的分流依据：
//   - 积分包：沿用社区版的 metrics 窗口（总积分门控 + 分桶明细 + 批次到期）
//   - token 包：官网口径是 5M 后降排队优先级、无硬上限（实测 230M/5M 仍可用，
//     个别模型在别的阈值受限）——窗口纯展示（aside 不门控），额度当作无限，
//     上游报错时再按错误码特判)

const CA_PROVIDER = "codearts-aksk"
// snap-access 基址可环境变量覆盖（调试/测试用）
const CA_SNAP_HOST = (process.env.CODEARTS_SNAP_HOST || "https://snap-access.cn-north-4.myhuaweicloud.com").replace(/\/+$/, "")
const CA_CHAT_API_BASE = `${CA_SNAP_HOST}/api/v2`
const CA_STATISTICS_URL = `${CA_SNAP_HOST}/snap-manager/v1/statistics/plugin`
const CA_MODELS_URL = `${CA_SNAP_HOST}/v1/model/builtin`
const CA_PACKAGE_CREDIT_PAGE_URL = `${CA_SNAP_HOST}/snap-manager/v1/package/credit/page`
const CA_OPS_CREDIT_OVERVIEW_URL = `${CA_SNAP_HOST}/v1/ops/credit/overview`
const CA_OPS_CREDIT_CAMPAIGN_URL = (id) => `${CA_SNAP_HOST}/v1/ops/credit/campaign/${encodeURIComponent(id)}?pageNum=1&pageSize=100`
const CA_PACKAGE_CREDIT_QUERIES = [
  { pageNum: 1, pageSize: 100, sortField: "created_time", sortOrder: "desc", packageTypes: ["basic", "ondemand"] },
  { pageNum: 1, pageSize: 100, packageTypes: ["bonus"] },
]
// snap-access 路由用的非签名头（签进签名里反而被拒）
const CA_SNAP_HEADERS = { "Agent-Type": "PromptCenter", "X-Language": "zh-cn" }

const CA_SESSION_LIMIT_ERROR = "TM.00001041" // 并发会话数已达上限(3个)
const CA_SESSION_RETRY_DELAYS_MS = [2000, 4000, 6000, 8000, 10000] // 最后一个重复
const CA_SESSION_RETRY_BUDGET_MS = 150000
const CA_MAX_OUTPUT_TOKENS = 65536 // RANGE_VALIDATOR 0..65536
const CA_SSE_PEEK_LIMIT = 16 * 1024
// 不显式要求时 reasoning 流进 content；显式开启才分到 reasoning_content
const CA_ENABLE_THINKING = { type: "enabled" }
// 积分制窗口（社区版口径）
const CA_CREDIT_METRIC_LABELS = {
  usageTotalPackageCredit: "总积分",
  usageBasicPackageCredit: "基础积分包",
  usageOnDemandPackageCredit: "按需积分包",
  usageBonusPackageCredit: "赠送积分包",
}
const CA_TOTAL_CREDIT_METRIC = "usageTotalPackageCredit"
const CA_MONTHLY_CREDIT_METRICS = ["usageTotalPackageCredit", "usageBasicPackageCredit"]
const CA_PACKAGE_TYPE_METRICS = { basic: "usageBasicPackageCredit", ondemand: "usageOnDemandPackageCredit", bonus: "usageBonusPackageCredit" }
const CA_CREDIT_BATCHES_TTL_MS = 10 * 60 * 1000
// 工具名上限：InferHub.001001017.413，超 64 字符的名字按 55+1+8(hash) 缩短
const CA_TOOL_NAME_LIMIT = 64
const CA_TOOL_NAME_KEEP = 55

// 静态目录（登录前 config 用）与已知上下文窗口；账号自己的清单来自
// /v1/model/builtin。视觉模型（-vl）小上下文、无工具调用，不列。
const CA_CATALOG = [
  ["GLM-5.2", "GLM-5.2"],
  ["GLM-5.1", "GLM-5.1"],
  ["glm-5.3-flash", "GLM-5.3 Flash"],
  ["openpangu-2.0-flash", "openPangu 2.0 Flash"],
  ["openpangu-2.0-pro", "openPangu 2.0 Pro"],
  ["deepseek-v4-flash-0731", "DeepSeek V4 Flash"],
  ["deepseek-v4-pro-0813", "DeepSeek V4 Pro"],
  ["deepseek-v4.1-flash", "DeepSeek V4.1 Flash"],
]
const CA_CONTEXT_WINDOWS = {
  "GLM-5.2": 202752,
  "glm-5.3-flash": 1048576,
  "deepseek-v4-flash": 1048576,
  "deepseek-v4-pro": 1048576,
  "deepseek-v4.1-flash": 1000000,
}

// ---- CodeArts 小工具 --------------------------------------------------------

const caNum = (v) => {
  if (typeof v === "number" && Number.isFinite(v)) return v
  if (typeof v === "string" && v.trim()) {
    const n = Number(v)
    if (Number.isFinite(n)) return n
  }
  return 0
}
const caClamp = (v) => Math.min(100, Math.max(0, v))
const caFirstOf = (...vs) => vs.find((v) => typeof v === "string" && v.trim())?.trim() ?? ""
function caSafeJson(text) {
  try {
    const v = JSON.parse(text)
    return v && typeof v === "object" ? v : null
  } catch {
    return null
  }
}
// 数字缩写（12345 → 1.2万）
function caFormat(n) {
  const v = Math.max(0, Number.isFinite(n) ? n : 0)
  if (v >= 1e8) return `${(v / 1e8).toFixed(1)}亿`
  if (v >= 1e4) return `${(v / 1e4).toFixed(1)}万`
  return String(Math.round(v))
}
// 官网日期（北京时区 "2026-10-21 15:59:59"）→ 毫秒
function caVendorDate(v) {
  if (typeof v === "number" && Number.isFinite(v) && v > 0) return v < 1e11 ? v * 1000 : v
  if (typeof v !== "string" || !v.trim()) return 0
  const s = v.trim()
  if (/^\d+$/.test(s)) return caVendorDate(Number(s))
  const local = /^(\d{4}-\d{2}-\d{2})(?:[ T](\d{2}:\d{2}(?::\d{2})?))?$/.exec(s)
  const at = local ? Date.parse(`${local[1]}T${local[2] ?? "00:00:00"}+08:00`) : Date.parse(s)
  return Number.isNaN(at) ? 0 : at
}
// 去掉模型 id 的日期后缀（deepseek-v4-flash-0731 → deepseek-v4-flash），用于查表
function caNormalizeModelId(id) {
  if (typeof id === "string" && id.length > 5) {
    const suffix = id.slice(-5)
    if (suffix.startsWith("-") && /^\d{4}$/.test(suffix.slice(1))) return id.slice(0, -5)
  }
  return id
}
function caPrettify(id) {
  return String(id)
    .split(/[-_]/)
    .filter(Boolean)
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ")
}
const caSleep = (ms) => new Promise((r) => setTimeout(r, ms))
// 每账号一个稳定会话 id（网关按 x-ot-session-id 计会话，上限 3）
function caSessionIdOf(auth) {
  return createHash("sha256").update(`ca-session:${String(auth?.key || "")}`).digest("hex").slice(0, 32)
}

// ---- CodeArts 签名与控制面 ---------------------------------------------------

// snap-access 的 SDK-HMAC-SHA256：比 agentarts 多签一个 x-sdk-content-sha256（正文
// 哈希）；POST 签 content-type，GET 不签。永久 AK/SK 无 security-token。
function caSign(method, url, ak, sk, bodyText = "") {
  const signed = { "x-sdk-content-sha256": sha256Hex(bodyText) }
  if (String(method).toUpperCase() !== "GET") signed["content-type"] = "application/json"
  return signSdk({ method, url, ak, sk, bodyText, headers: signed })
}

// snap-access 的 JSON 调用（统计/模型/积分明细）
async function caSnapRequest(ak, sk, method, url, payload) {
  const bodyText = payload === undefined ? "" : JSON.stringify(payload)
  const headers = caSign(method, url, ak, sk, bodyText)
  Object.assign(headers, CA_SNAP_HEADERS)
  let res
  try {
    res = await fetch(url, {
      method,
      headers,
      ...(payload === undefined ? {} : { body: bodyText }),
      signal: AbortSignal.timeout(20000),
    })
  } catch (e) {
    return { status: 0, ok: false, json: null, text: String(e?.message ?? e) }
  }
  const text = await res.text()
  return { status: res.status, ok: res.ok, json: caSafeJson(text), text }
}

function fetchCaStatistics(ak, sk) {
  return caSnapRequest(ak, sk, "GET", CA_STATISTICS_URL)
}

function fetchCaBuiltinModels(ak, sk) {
  return caSnapRequest(ak, sk, "GET", CA_MODELS_URL)
}

// 积分批次（各自到期时间）：积分制账号的 runsOut/周期重置来源；token 制账号上
// 这些接口 404（未发布），返回 undefined 由调用方兜底。
async function fetchCaCreditBatches(ak, sk) {
  const batches = []
  let reached = false
  for (const query of CA_PACKAGE_CREDIT_QUERIES) {
    const r = await caSnapRequest(ak, sk, "POST", CA_PACKAGE_CREDIT_PAGE_URL, query)
    const list = r.json?.data?.list
    if (!r.ok || !Array.isArray(list)) continue
    reached = true
    for (const p of list) {
      const metric = CA_PACKAGE_TYPE_METRICS[p?.packageType]
      if (!metric) continue
      const amount = caNum(p.creditAmount)
      batches.push({ metric, amount, left: Math.max(0, amount - caNum(p.creditUsed)), expiresAt: caVendorDate(p.expiredTime) })
    }
  }
  const overview = await caSnapRequest(ak, sk, "GET", CA_OPS_CREDIT_OVERVIEW_URL)
  const campaigns = overview.json?.data?.items
  if (overview.ok && Array.isArray(campaigns)) {
    reached = true
    for (const c of campaigns) {
      const left = caNum(c?.totalClaimed) - caNum(c?.totalConsumed) - caNum(c?.totalExpired)
      if (left <= 0 || c.campaignId === undefined || c.campaignId === null) continue
      const page = await caSnapRequest(ak, sk, "GET", CA_OPS_CREDIT_CAMPAIGN_URL(c.campaignId))
      for (const b of Array.isArray(page.json?.data?.benefits) ? page.json.data.benefits : []) {
        const amount = caNum(b?.claimedAmount)
        batches.push({
          metric: CA_PACKAGE_TYPE_METRICS.bonus,
          amount,
          left: Math.max(0, amount - caNum(b.consumedAmount) - caNum(b.expiredAmount)),
          expiresAt: caVendorDate(b.expireAt),
        })
      }
    }
  }
  return reached ? batches : undefined
}

// 每账号的积分批次缓存（10 分钟）
const caBatchesState = new Map()
function caBatchesOf(ak, sk) {
  const st = caBatchesState.get(ak) ?? { at: 0, batches: undefined }
  if (!st.at || Date.now() - st.at > CA_CREDIT_BATCHES_TTL_MS) {
    return fetchCaCreditBatches(ak, sk)
      .catch(() => undefined)
      .then((b) => {
        if (b) caBatchesState.set(ak, { at: Date.now(), batches: b })
        else caBatchesState.set(ak, { at: Date.now(), batches: st.batches })
        return b ?? st.batches
      })
  }
  return Promise.resolve(st.batches)
}

// ---- CodeArts 用量 -------------------------------------------------------------

/**
 * statistics/plugin → magpie 窗口，按 package 类型分流：
 *  - is_credit_package（或有积分指标）：社区版口径——「总积分」是唯一门控窗口，
 *    分桶 aside 展示，各批次自己的到期时间作 runsOut；
 *  - is_token_package：官网口径是 5M 后降排队优先级、无硬上限（实测超 4600%
 *    仍可用）——token 窗口纯展示（aside），额度当作无限；
 *  - 都没有：只报套餐名，不报 error（账号不误判为耗尽）。
 */
function caUsageOf(raw, batches, now = Date.now()) {
  let data = raw
  if (raw && typeof raw.code === "number") {
    if (raw.code !== 0) return { error: `CodeArts code ${raw.code}${caFirstOf(raw.message, raw.msg) ? `: ${caFirstOf(raw.message, raw.msg)}` : ""}`, windows: [], signIn: "kept" }
    data = raw.data
  }
  if (!data || typeof data !== "object") return { error: "订阅查询没有内容", windows: [], signIn: "kept" }
  const pkg = data.package ?? {}
  const plan = caFirstOf(pkg.package_name_cn, pkg.package_name_en, pkg.spec_code)
  const metrics = Array.isArray(data.metrics) ? data.metrics : []
  const known = Array.isArray(batches) ? batches : []
  const windows = []

  const creditMetrics = metrics.filter((m) => CA_CREDIT_METRIC_LABELS[m?.name])
  if (creditMetrics.length || pkg.is_credit_package) {
    // 积分制（社区版逻辑照抄）
    const planEnds = known.filter((b) => b.metric === CA_PACKAGE_TYPE_METRICS.basic && b.expiresAt > now).map((b) => b.expiresAt)
    const reset = planEnds.length ? Math.min(...planEnds) : caVendorDate(data.end_date)
    const metricOf = new Map()
    for (const item of creditMetrics) {
      const name = CA_CREDIT_METRIC_LABELS[item?.name]
      if (!name) continue
      const limit = caNum(item.package_credit_amount)
      const remain = caNum(item.package_credit_remain)
      if (limit <= 0 && remain <= 0) continue // 空桶不展示
      const used = Math.max(0, limit - remain)
      const expiring = caNum(item.package_credit_expiring_amount)
      const w = {
        name,
        used: caClamp(limit > 0 ? (used / limit) * 100 : 0),
        display: `${caFormat(used)} / ${caFormat(limit)}${expiring > 0 ? ` · ${caFormat(expiring)} 即将过期` : ""}`,
        amount: used,
        limit,
        unit: "credits",
        ...(CA_MONTHLY_CREDIT_METRICS.includes(item.name) && reset ? { resetsAt: new Date(reset).toISOString() } : {}),
        ...(name !== CA_CREDIT_METRIC_LABELS[CA_TOTAL_CREDIT_METRIC] ? { aside: true } : {}),
      }
      metricOf.set(w, item.name)
      windows.push(w)
    }
    // 各分桶自己的批次到期（总积分看全部批次，基础包只看自家的）
    for (const w of windows) {
      const metric = metricOf.get(w)
      if (metric === CA_PACKAGE_TYPE_METRICS.basic) continue
      const own = known.filter((b) => (metric === CA_TOTAL_CREDIT_METRIC ? b.metric !== CA_PACKAGE_TYPE_METRICS.basic : b.metric === metric))
      const live = own.filter((b) => b.left > 0 && b.expiresAt > now)
      const left = Math.max(0, w.limit - w.amount)
      if (live.length && left > 0) {
        const at = Math.min(...live.map((b) => b.expiresAt))
        w.runsOutAt = new Date(at).toISOString()
        w.runsOut = Math.min(Math.max(...live.filter((b) => b.expiresAt === at).map((b) => b.left)), left)
      }
    }
    // 总积分排最前
    windows.sort((a, b) => (a.name === CA_CREDIT_METRIC_LABELS[CA_TOTAL_CREDIT_METRIC] ? -1 : b.name === CA_CREDIT_METRIC_LABELS[CA_TOTAL_CREDIT_METRIC] ? 1 : 0))
  } else {
    // token 制 / 其他：纯展示不门控
    const endsAt = caVendorDate(data.end_date)
    for (const m of metrics) {
      if (m?.name !== "usageTokenChatMessages") continue
      if (m?.show === false) continue
      const used = caNum(m.usage_token_num)
      const limit = caNum(m.package_token_amount)
      if (limit <= 0 && used <= 0) continue
      windows.push({
        name: "Token 用量（软限）",
        used: caClamp(limit > 0 ? (used / limit) * 100 : 0),
        display: `${caFormat(used)} / ${caFormat(limit)} tokens · 超过后降低排队优先级，无硬上限`,
        amount: used,
        limit,
        unit: "tokens",
        ...(endsAt ? { resetsAt: new Date(endsAt).toISOString() } : {}),
        aside: true,
      })
    }
  }
  return { plan: plan || undefined, windows, signIn: "kept" }
}

// ---- CodeArts 工具名缩短/还原 ---------------------------------------------------

function caToolNameSlots(body) {
  const slots = []
  const slot = (obj, key) => {
    if (obj && typeof obj === "object" && typeof obj[key] === "string") slots.push({ obj, key })
  }
  for (const t of Array.isArray(body.tools) ? body.tools : []) slot(t?.function, "name")
  for (const f of Array.isArray(body.functions) ? body.functions : []) slot(f, "name")
  const choice = body.tool_choice
  if (choice && typeof choice === "object") slot(choice.function, "name")
  if (body.function_call && typeof body.function_call === "object") slot(body.function_call, "name")
  for (const m of Array.isArray(body.messages) ? body.messages : []) {
    if (!m || typeof m !== "object") continue
    for (const c of Array.isArray(m.tool_calls) ? m.tool_calls : []) slot(c?.function, "name")
    slot(m.function_call, "name")
    if (m.role === "tool" || m.role === "function") slot(m, "name")
  }
  return slots
}

function caCutToolName(name, salt) {
  let head = name.slice(0, CA_TOOL_NAME_KEEP)
  if (/[\uD800-\uDBFF]$/.test(head)) head = head.slice(0, -1) // 不切半个代理对
  const hex = createHash("sha256").update(salt ? `${name}\u0000${salt}` : name).digest("hex")
  return `${head}_${hex.slice(0, 8)}`
}

// 同一组名字每次切得一致（固定顺序）；返回 发送名 → 原名 的映射
function caShortenToolNames(body) {
  const slots = caToolNameSlots(body)
  if (!slots.some((s) => s.obj[s.key].length > CA_TOOL_NAME_LIMIT)) return null
  const taken = new Set(slots.map((s) => s.obj[s.key]).filter((n) => n.length <= CA_TOOL_NAME_LIMIT))
  const names = new Map()
  const long = [...new Set(slots.map((s) => s.obj[s.key]).filter((n) => n.length > CA_TOOL_NAME_LIMIT))].sort()
  for (const name of long) {
    let cut = caCutToolName(name, 0)
    for (let salt = 1; taken.has(cut) || names.has(cut); salt += 1) cut = caCutToolName(name, salt)
    names.set(cut, name)
  }
  const short = new Map([...names].map(([cut, name]) => [name, cut]))
  for (const s of slots) {
    const cut = short.get(s.obj[s.key])
    if (cut) s.obj[s.key] = cut
  }
  return names
}

// 整个 completion 里把工具名换回原样
function caRestoreToolNames(completion, names) {
  if (!names) return completion
  for (const choice of Array.isArray(completion?.choices) ? completion.choices : []) {
    const msg = choice?.message
    if (!msg || typeof msg !== "object") continue
    for (const c of Array.isArray(msg.tool_calls) ? msg.tool_calls : []) {
      const name = c?.function?.name
      if (typeof name === "string" && names.has(name)) c.function.name = names.get(name)
    }
    if (msg.function_call && names.has(msg.function_call.name)) msg.function_call.name = names.get(msg.function_call.name)
  }
  return completion
}

// 流式响应里把工具名换回原样：整名一次到位；网关分片发名时，已发的前缀之外
// 暂存、成整名后补齐；不含工具名的事件原字节透传
function caRestoreToolNamesInStream(stream, names) {
  if (!names) return stream
  const cuts = [...names.keys()]
  const calls = new Map()
  const enc = new TextEncoder()
  const dec = new TextDecoder()
  let pending = ""
  const named = (key, piece) => {
    const c = calls.get(key) ?? { got: "", sent: 0 }
    calls.set(key, c)
    if (names.has(piece)) {
      const own = names.get(piece)
      c.got = own
      c.sent = own.length
      return own
    }
    c.got += piece
    let out
    if (names.has(c.got)) {
      const own = names.get(c.got)
      out = own.slice(c.sent)
      c.sent = own.length
      c.got = own
    } else if (c.got.length < CA_TOOL_NAME_LIMIT && cuts.some((cut) => cut.startsWith(c.got))) {
      const upTo = Math.min(c.got.length, CA_TOOL_NAME_KEEP)
      out = upTo > c.sent ? c.got.slice(c.sent, upTo) : ""
      c.sent = Math.max(c.sent, upTo)
    } else {
      out = c.got.slice(c.sent)
      c.sent = c.got.length
    }
    return out
  }
  const held = () => {
    const choices = []
    for (const [key, c] of calls) {
      if (c.sent >= c.got.length) continue
      const [ci, ti] = key.split(":").map(Number)
      choices.push({ index: ci, delta: { tool_calls: [{ index: ti, function: { name: c.got.slice(c.sent) } }] } })
      c.sent = c.got.length
    }
    return choices.length ? `data: ${JSON.stringify({ choices })}\n\n` : ""
  }
  const line = (l) => {
    const t = l.replace(/\r$/, "")
    if (!t.startsWith("data:")) return l
    const payload = t.slice(5).trim()
    if (payload === "[DONE]") return held() + l
    if (!payload.includes("tool_calls") && !payload.includes("function_call")) return l
    const ev = caSafeJson(payload)
    if (!ev || !Array.isArray(ev.choices)) return l
    let changed = false
    for (const [ci, choice] of ev.choices.entries()) {
      const delta = choice?.delta
      if (!delta || typeof delta !== "object") continue
      const index = Number.isInteger(choice.index) ? choice.index : ci
      for (const [k, call] of (Array.isArray(delta.tool_calls) ? delta.tool_calls : []).entries()) {
        const fn = call?.function
        if (!fn || typeof fn.name !== "string") continue
        const out = named(`${index}:${Number.isInteger(call.index) ? call.index : k}`, fn.name)
        if (out !== fn.name) {
          fn.name = out
          changed = true
        }
      }
      if (delta.function_call && typeof delta.function_call.name === "string") {
        const out = named(`${index}:fc`, delta.function_call.name)
        if (out !== delta.function_call.name) {
          delta.function_call.name = out
          changed = true
        }
      }
    }
    return changed ? `data: ${JSON.stringify(ev)}${l.endsWith("\r") ? "\r" : ""}` : l
  }
  const reader = stream.getReader()
  return new ReadableStream({
    async pull(controller) {
      for (;;) {
        const { done, value } = await reader.read()
        if (done) {
          let rest = pending + dec.decode()
          pending = ""
          if (rest) rest = line(rest)
          rest += held()
          if (rest) controller.enqueue(enc.encode(rest))
          controller.close()
          return
        }
        pending += dec.decode(value, { stream: true })
        const cut = pending.lastIndexOf("\n")
        if (cut < 0) continue
        const whole = pending.slice(0, cut)
        pending = pending.slice(cut + 1)
        controller.enqueue(enc.encode(whole.split("\n").map(line).join("\n") + "\n"))
        return
      }
    },
    cancel(reason) {
      return reader.cancel(reason)
    },
  })
}

// ---- CodeArts chat -------------------------------------------------------------

// 请求体整形（社区版 prepareChatBody）：注入 thinking（默认显式开启，让推理分到
// reasoning_content 而不是混进 content）、钳 max_tokens、强制流式（网关只按
// 流式计量，非流式请求由响应侧折叠回来）、缩短超长工具名
function caFitBody(parsed) {
  if (!parsed || typeof parsed.model !== "string" || !Array.isArray(parsed.messages)) return null
  const body = { ...parsed }
  const names = caShortenToolNames(body)
  const injected = body.thinking === undefined
  if (injected) body.thinking = CA_ENABLE_THINKING
  for (const k of ["max_tokens", "max_completion_tokens"]) {
    if (typeof body[k] === "number" && body[k] > CA_MAX_OUTPUT_TOKENS) body[k] = CA_MAX_OUTPUT_TOKENS
  }
  const fold = body.stream !== true
  body.stream = true
  return { body: JSON.stringify(body), fold, injected, names }
}

// 从响应里识别上游错误码（InferHub.ModelArts.81111.429 这类）
function caErrorCodeOf(text) {
  const m = /"(?:error_code|code)"\s*:\s*"((?:[A-Za-z]+\.)*[A-Za-z]*[0-9][0-9A-Za-z.]*)"/.exec(String(text ?? ""))
  return m ? m[1] : ""
}
function caErrorMessageOf(text) {
  const m = /"(?:error_msg|message)"\s*:\s*"((?:[^"\\]|\\.)*)"/.exec(String(text ?? ""))
  if (!m) return ""
  try {
    return JSON.parse(`"${m[1]}"`)
  } catch {
    return m[1]
  }
}
// 嵌在 200 里的错误该按什么状态回
function caEmbeddedErrorStatus(code) {
  if (/4291|8111\d|(^|\.)429(\.|$)/.test(String(code ?? ""))) return 429
  if (/(^|\.)40[0-4](\.|$)|InferHub\.400[0-9]\./.test(String(code ?? ""))) return 400
  if (/InferHub\.001001020\.406|not multimodal/i.test(String(code ?? ""))) return 400
  return 502
}

// 首个 data 事件带内容（delta 有 role/content/reasoning/tool_calls）即真实回答
function caSseHasContent(text) {
  for (const m of String(text).matchAll(/^data:\s*(.+)$/gm)) {
    const payload = m[1].trim()
    if (!payload || payload === "[DONE]") continue
    const ev = caSafeJson(payload)
    const d = ev?.choices?.[0]?.delta ?? ev?.choices?.[0]?.message
    if (d && (d.role || d.content || d.reasoning_content || (Array.isArray(d.tool_calls) && d.tool_calls.length))) return true
  }
  return false
}

// 200 的流先读个头再判定：真回答（回放已读字节）还是内嵌错误
function caClassifyHead(text, done) {
  if (caSseHasContent(text)) return "answer"
  if (done) {
    const j = caSafeJson(text)
    if (Array.isArray(j?.choices)) return "answer"
  }
  const code = caErrorCodeOf(text)
  if (code) return done || /\n/.test(text.slice(text.indexOf(code))) ? code : undefined
  if (done || /^data:\s*\[DONE\]\s*$/m.test(text)) return "answer"
  return undefined
}

async function caPeekAnswer(res) {
  const head = { code: "", text: "", chunks: [], reader: null, decoder: new TextDecoder() }
  if (!res.body) return head
  head.reader = res.body.getReader()
  let done = false
  for (;;) {
    const verdict = caClassifyHead(head.text, done)
    if (verdict) {
      if (verdict !== "answer") head.code = verdict
      break
    }
    if (head.text.length >= CA_SSE_PEEK_LIMIT) break
    const r = await head.reader.read()
    if (r.done) {
      done = true
      continue
    }
    head.chunks.push(new Uint8Array(r.value))
    head.text += head.decoder.decode(r.value, { stream: true })
  }
  if (head.code) void head.reader.cancel().catch(() => {})
  return head
}

// 已读字节 + 剩余流拼回一个完整流
function caReplayBody(head) {
  let i = 0
  return new ReadableStream({
    async pull(controller) {
      if (i < head.chunks.length) {
        controller.enqueue(head.chunks[i++])
        return
      }
      const { done, value } = head.reader ? await head.reader.read() : { done: true }
      if (done) {
        controller.close()
        return
      }
      controller.enqueue(new Uint8Array(value))
    },
    cancel(reason) {
      void head.reader?.cancel(reason).catch(() => {})
    },
  })
}

const caStreamHeaders = (headers) => {
  const out = new Headers(headers)
  out.delete("content-encoding")
  out.delete("content-length")
  return out
}

function caErrorResponse(status, code, message, extraHeaders = {}) {
  const body = JSON.stringify({
    error: {
      message: code ? `${message}（${code}）` : message,
      type: status === 429 ? "rate_limit_error" : "api_error",
      code: code || null,
    },
  })
  return new Response(body, { status, headers: { "content-type": "application/json", ...extraHeaders } })
}

// 非流式请求：把流式答案折叠成单个 chat.completion（复用 officeace 的聚合），
// 工具名在折叠结果里换回原样
async function caFoldAnswer(res, head, names, fallbackModel) {
  let text = head.text + head.decoder.decode()
  for (;;) {
    const { done, value } = head.reader ? await head.reader.read() : { done: true }
    if (done) break
    text += head.decoder.decode(value, { stream: true })
  }
  head.reader?.releaseLock?.()
  const folded = await aggregated(new Response(text, { status: res.status, statusText: res.statusText, headers: { "content-type": "text/event-stream" } }), fallbackModel)
  if (!names) return folded
  const j = JSON.parse(await folded.text())
  caRestoreToolNames(j, names)
  return new Response(JSON.stringify(j), { status: folded.status, statusText: folded.statusText, headers: { "content-type": "application/json" } })
}

// codearts 的每个 chat 都走这里：整形 → 签名 → 会话头 → 发送 → 错误改写。
// TM.00001041（3 会话上限）按预算退避重试，超时按 429 交回 magpie 转移；
// 模型拒绝 thinking 参数时按原请求重发一次；401/403 标记账号失效。
function caGatewayFetch(auth) {
  const ak = String(auth.key || "")
  const sk = String(auth.metadata?.sk || "")
  const sessionId = caSessionIdOf(auth)
  return async (input, init) => {
    const req = input instanceof Request ? input : null
    const url = req ? req.url : String(input)
    const method = String(init?.method ?? req?.method ?? "POST").toUpperCase()
    const baseHeaders = new Headers(init?.headers ?? req?.headers)
    baseHeaders.delete("authorization")
    baseHeaders.delete("x-api-key")
    baseHeaders.delete("content-length")
    let body = init?.body
    if (body === undefined && req) body = await req.clone().text()
    const parsed = typeof body === "string" && body ? caSafeJson(body) : null
    const chat = caFitBody(parsed)
    if (chat) body = chat.body
    const fallbackModel = typeof parsed?.model === "string" ? parsed.model : ""

    const send = async () => {
      const signed = caSign(method, url, ak, sk, typeof body === "string" ? body : "")
      const headers = new Headers(baseHeaders)
      for (const [k, v] of Object.entries(signed)) headers.set(k, v)
      // 会话/追踪头不签名：网关按它们路由
      headers.set("Chat-Id", sessionId)
      headers.set("Session-Id", sessionId)
      headers.set("x-ot-session-id", sessionId)
      headers.set("user-session-id", sessionId)
      headers.set("x-ot-parent-session-id", "")
      headers.set("x-ot-trace-id", randomBytes(16).toString("hex"))
      headers.set("x-ot-span-id", randomBytes(8).toString("hex"))
      headers.set("x-snap-traceid", randomBytes(16).toString("hex"))
      headers.set("lang", "en")
      return fetch(url, { ...init, method, headers, ...(typeof body === "string" ? { body } : {}), redirect: "error" })
    }

    const started = Date.now()
    for (let attempt = 0; ; attempt += 1) {
      let res
      try {
        res = await send()
      } catch (e) {
        return caErrorResponse(502, "", `CodeArts 网络错误：${e?.message ?? e}`)
      }
      if (res.status === 429) return res // 网关自己的限流：交给 magpie 退避/转移

      let text = ""
      let code = ""
      if (res.ok) {
        const head = await caPeekAnswer(res)
        if (!head.code) {
          if (chat?.fold) return await caFoldAnswer(res, head, chat?.names, fallbackModel)
          const stream = caRestoreToolNamesInStream(caReplayBody(head), chat?.names)
          return new Response(stream, { status: res.status, statusText: res.statusText, headers: caStreamHeaders(res.headers) })
        }
        text = head.text
        code = head.code
      } else {
        text = await res.text().catch(() => "")
        code = caErrorCodeOf(text)
      }

      if (res.status === 401) {
        const out = new Headers(res.headers)
        out.set("X-Magpie-Sign-In", "expired")
        return new Response(text, { status: res.status, statusText: res.statusText, headers: out })
      }
      if (res.status === 403) {
        // 永久 AK/SK 没有「登录失效」。403 的语义是模型级权益拒绝（实测 glm-5.3
        // 回 TM.000010051「当前所选模型的使用权益已耗尽，可选择如下模型…」）：
        // 按 magpie 的模型拒绝方言改写（modelRefused 认 403 + ModelUnserved 词、
        // 正文不落 quotaWords），路由只冷却该模型、账号其他模型照常；不带
        // X-Magpie-Sign-In，账号永不标记失效（magpie 文档：账号不能用某模型
        // 时用 403/404 而非 401）。
        const list = /可选择如下模型[:：]\s*(\[[^\]]*\])/.exec(text)?.[1] ?? ""
        return caErrorResponse(403, code, `模型未开通：${fallbackModel || "该模型"} 不在此账号的可用模型清单${list ? `（可用：${list}）` : ""}`)
      }
      // thinking 是插件自己注入的：模型拒绝就按原请求重发一次
      if (res.status === 400 && chat?.injected && /thinking/i.test(text)) {
        chat.injected = false
        const without = caSafeJson(chat.body) ?? {}
        delete without.thinking
        body = JSON.stringify(without)
        continue
      }
      if (code === CA_SESSION_LIMIT_ERROR || text.includes(CA_SESSION_LIMIT_ERROR)) {
        const wait = CA_SESSION_RETRY_DELAYS_MS[Math.min(attempt, CA_SESSION_RETRY_DELAYS_MS.length - 1)]
        if (Date.now() - started + wait <= CA_SESSION_RETRY_BUDGET_MS) {
          await caSleep(wait)
          continue
        }
        return caErrorResponse(429, CA_SESSION_LIMIT_ERROR, caFirstOf(caErrorMessageOf(text), "并发会话数已达上限，请稍后再试"))
      }
      if (!res.ok) {
        const out = new Headers(res.headers)
        out.delete("content-length")
        out.delete("content-encoding")
        return new Response(text, { status: res.status, statusText: res.statusText, headers: out })
      }
      return caErrorResponse(caEmbeddedErrorStatus(code), code, caFirstOf(caErrorMessageOf(text), "上游返回了错误"))
    }
  }
}

// ---- CodeArts 模型 --------------------------------------------------------------

function caModelEntry({ id, name, context }) {
  return {
    id,
    providerID: CA_PROVIDER,
    name,
    api: { id, url: CA_CHAT_API_BASE, npm: NPM },
    status: "active",
    headers: {},
    options: {},
    cost: { input: 0, output: 0, cache: { read: 0, write: 0 } },
    limit: { context: context || 128000, output: CA_MAX_OUTPUT_TOKENS },
    capabilities: {
      temperature: true,
      reasoning: true,
      attachment: false,
      toolcall: true,
      input: { text: true, image: false, audio: false, video: false, pdf: false },
      output: { text: true, image: false, audio: false, video: false, pdf: false },
      interleaved: false,
    },
    release_date: "",
    variants: {},
  }
}

function caStaticModels() {
  return Object.fromEntries(CA_CATALOG.map(([id, name]) => [id, caModelEntry({ id, name, context: CA_CONTEXT_WINDOWS[caNormalizeModelId(id)] })]))
}

// builtin 清单 → 模型表：视觉模型（-vl）小上下文、无工具调用，不列
function caParseBuiltin(list) {
  const out = {}
  const seen = new Set()
  for (const item of Array.isArray(list) ? list : []) {
    if (!item || typeof item !== "object") continue
    const id = typeof item.model_id === "string" ? item.model_id : ""
    if (!id || seen.has(id) || item.enable === false) continue
    const base = caNormalizeModelId(id)
    if (/-vl(-|$)/i.test(base)) continue
    seen.add(id)
    const rawName = typeof item.model_name === "string" && item.model_name ? caNormalizeModelId(item.model_name) : ""
    out[id] = caModelEntry({
      id,
      name: rawName || caPrettify(base),
      context: caNum(item.context_window) || CA_CONTEXT_WINDOWS[base],
    })
  }
  return out
}

// ---- the plugin --------------------------------------------------------------------

function makePlugin() {
  return async () => ({
    config: async (config) => {
      config.provider ??= {}
      config.provider[PROVIDER] ??= {}
      const p = config.provider[PROVIDER]
      p.name ??= "OfficeAce (AK/SK)"
      p.npm ??= NPM
      p.api ??= DEFAULT_GATEWAY + "/v2"
      p.models = { ...staticModels(), ...(p.models ?? {}) }
    },
    provider: {
      id: PROVIDER,
      // the account's own list, when its gateway answers; else the list above
      async models(provider, { auth } = {}) {
        if (!basicOf(auth)) return provider.models
        try {
          const ms = await liveModels(auth)
          if (!ms.length) return provider.models
          return Object.fromEntries(ms.map((m) => [m.id, modelOf(provider, { ...m, baseUrl: auth.metadata?.baseUrl })]))
        } catch {
          return provider.models
        }
      },
    },
    auth: {
      provider: PROVIDER,
      // Nothing renews: the AK/SK are permanent and the Basic key they buy
      // does not end. An account stops only when its credits do.
      async loader(getAuth) {
        const auth = await getAuth()
        if (auth?.type !== "api" || !auth.key) return {}
        if (!basicOf(auth)) return {}
        return {
          baseURL: baseUrlOf(auth),
          apiKey: "",
          fetch: gatewayFetch(auth),
        }
      },
      // the account's credits, as the OfficeAce client's subscription card
      async usage(getAuth) {
        const auth = await getAuth()
        if (auth?.type !== "api" || !auth.key || !auth.metadata?.sk)
          return { error: "not signed in with an AK/SK", signIn: "kept" }
        try {
          const res = await subscriptionOf(auth)
          if (!res.ok) return { error: `OfficeAce 的订阅查询失败：HTTP ${res.status}`, signIn: "kept" }
          const sub = res.json
          if (!sub) return { error: "OfficeAce 的订阅查询没有返回内容", signIn: "kept" }
          const why = vendorError(sub)
          if (why) return { error: `OfficeAce 订阅：${why}`, signIn: "kept" }
          return { ...usageOf(sub), signIn: "kept" }
        } catch (e) {
          return { error: redacted(auth, e?.message ?? String(e)), signIn: "kept" }
        }
      },
      // the day's rewards, as the subscription card's claim takes them: one
      // idempotent POST, the balance read before and after to say what came.
      // The same call hands over the daily sign-in reward and any one-time
      // newcomer gift, so there is nothing else to press.
      async checkin(getAuth) {
        const auth = await getAuth()
        if (auth?.type !== "api" || !auth.key || !auth.metadata?.sk)
          return { outcome: "failed", message: "OfficeAce 未用 AK/SK 登录" }
        try {
          // A balance read that fails for another reason doesn't block the
          // claim; a refused sign-in does.
          const read = await subscriptionOf(auth)
          if (read.status === 401 || read.status === 403)
            return { outcome: "failed", message: "订阅被拒绝；AK/SK 可能已失效或被吊销" }
          if (read.status === 429) return { outcome: "failed", message: "订阅查询被限流；请稍后重试" }
          const before = baselineOf(read)

          const claim = await claimBonus(auth)
          if (claim.status === 401 || claim.status === 403)
            return { outcome: "failed", message: "领取被拒绝；AK/SK 可能已失效或被吊销" }
          if (claim.status === 429) return { outcome: "failed", message: "领取被限流；请稍后重试" }
          if (!claim.ok) {
            const why = redacted(auth, vendorError(claim.json) || claim.text)
            return { outcome: "failed", message: `领取失败：HTTP ${claim.status}${why ? `: ${why}` : ""}` }
          }
          const why = vendorError(claim.json)
          if (why) return { outcome: "failed", message: `领取被拒绝：${why}` }

          // The claim answer carries only what this claim granted (empty
          // when today was already settled), not the ledger: read the
          // subscription again for the full balance. A failed re-read must
          // not turn a claim that succeeded into a retryable failure.
          let updated = null
          try {
            updated = await subscriptionOf(auth)
          } catch {}
          const after = baselineOf(updated)
          if (!before || !after) return { outcome: "done", message: "已领取（余额暂不可读）" }
          const gained = Math.floor(gainedBetween(before, after))
          if (gained > 0) return { outcome: "claimed", credit: gained, message: `领取了 ${gained} 积分` }
          return { outcome: "done", message: "今天没有可领的奖励了" }
        } catch (e) {
          return { outcome: "failed", message: redacted(auth, e?.message ?? String(e)) }
        }
      },
      methods: [
        {
          type: "api",
          label: "永久 AK/SK（华为云 IAM）",
          // keyless: magpie 不再单独弹一个 API key 输入框（否则会和下面的
          // ak/sk prompts 重复问一遍），全部由 prompts 收齐后交给 authorize。
          keyless: true,
          prompts: [
            {
              type: "text",
              key: "ak",
              message: "Access Key (AK)",
              placeholder: "AK…",
              validate: (v) => (String(v ?? "").trim().length >= 10 ? undefined : "AK 至少 10 个字符"),
            },
            {
              type: "password",
              key: "sk",
              message: "Secret Key (SK)",
              placeholder: "SK…",
              validate: (v) => (String(v ?? "").trim().length >= 16 ? undefined : "SK 至少 16 个字符"),
            },
          ],
          async authorize(inputs) {
            const ak = String(inputs?.ak ?? "").trim()
            const sk = String(inputs?.sk ?? "").trim()
            if (!ak || !sk) return { type: "failed", error: "AK 和 SK 都不能为空" }
            try {
              // the permission check is the validation: wrong keys are told
              // here, and the gateway + Basic key it gives are stored.
              const info = await fetchPermission(ak, sk)
              if (!info.appKey || !info.baseUrl) {
                throw new Error("该账号没有可用的模型网关；请确认 OfficeAce 套餐已开通")
              }
              return {
                type: "success",
                key: ak,
                metadata: {
                  sk,
                  appKey: info.appKey,
                  appSecret: info.appSecret,
                  baseUrl: info.baseUrl,
                  ...(info.accountId ? { accountId: info.accountId } : {}),
                },
              }
            } catch (e) {
              return { type: "failed", error: redacted({ key: ak, metadata: { sk } }, e?.message ?? String(e)) }
            }
          },
        },
      ],
    },
  })
}

export const OfficeAceAkskPlugin = makePlugin()

// ---- the CodeArts plugin ------------------------------------------------------

function makeCodeartsPlugin() {
  return async () => ({
    config: async (config) => {
      config.provider ??= {}
      config.provider[CA_PROVIDER] ??= {}
      const p = config.provider[CA_PROVIDER]
      p.name ??= "CodeArts (AK/SK)"
      p.npm ??= NPM
      p.api ??= CA_CHAT_API_BASE
      p.models = { ...caStaticModels(), ...(p.models ?? {}) }
    },
    provider: {
      id: CA_PROVIDER,
      // 账号自己的清单（builtin），取不到时回退静态目录
      async models(provider, { auth } = {}) {
        if (auth?.type !== "api" || !auth.key || !auth.metadata?.sk) return provider.models
        try {
          const res = await fetchCaBuiltinModels(auth.key, auth.metadata.sk)
          if (!res.ok) return provider.models
          const out = caParseBuiltin(res.json?.builtinModels)
          if (!Object.keys(out).length) return provider.models
          return out
        } catch {
          return provider.models
        }
      },
    },
    auth: {
      provider: CA_PROVIDER,
      // 网关每账号 3 个并发会话；magpie 按此限流，剩余的偶发上限由 chat 侧重试兜底
      maxConcurrency: 3,
      // 永久 AK/SK 直签聊天，无需 Basic key
      async loader(getAuth) {
        const auth = await getAuth()
        if (auth?.type !== "api" || !auth.key || !auth.metadata?.sk) return {}
        return {
          baseURL: CA_CHAT_API_BASE,
          apiKey: "",
          fetch: caGatewayFetch(auth),
        }
      },
      // 套餐与用量：token 制纯展示（额度当作无限），积分制照抄社区版
      async usage(getAuth) {
        const auth = await getAuth()
        if (auth?.type !== "api" || !auth.key || !auth.metadata?.sk) return { error: "not signed in", windows: [], signIn: "kept" }
        try {
          const res = await fetchCaStatistics(auth.key, auth.metadata.sk)
          if (res.status === 401 || res.status === 403) return { error: `订阅被拒绝：HTTP ${res.status}（AK/SK 可能已失效）`, windows: [], signIn: "kept" }
          if (!res.ok) return { error: `订阅查询失败：HTTP ${res.status}`, windows: [], signIn: "kept" }
          const sub = res.json
          if (!sub) return { error: "订阅查询没有内容", windows: [], signIn: "kept" }
          const needBatches = sub?.package?.is_credit_package || (Array.isArray(sub?.metrics) && sub.metrics.some((m) => CA_CREDIT_METRIC_LABELS[m?.name]))
          const batches = needBatches ? await caBatchesOf(auth.key, auth.metadata.sk) : undefined
          return caUsageOf(sub, batches)
        } catch (e) {
          return { error: redacted(auth, e?.message ?? String(e)), windows: [], signIn: "kept" }
        }
      },
      methods: [
        {
          type: "api",
          label: "永久 AK/SK（华为云 IAM，与 OfficeAce 同一账号）",
          keyless: true,
          prompts: [
            {
              type: "text",
              key: "ak",
              message: "Access Key (AK)",
              placeholder: "AK…",
              validate: (v) => (String(v ?? "").trim().length >= 10 ? undefined : "AK 至少 10 个字符"),
            },
            {
              type: "password",
              key: "sk",
              message: "Secret Key (SK)",
              placeholder: "SK…",
              validate: (v) => (String(v ?? "").trim().length >= 16 ? undefined : "SK 至少 16 个字符"),
            },
          ],
          async authorize(inputs) {
            const ak = String(inputs?.ak ?? "").trim()
            const sk = String(inputs?.sk ?? "").trim()
            if (!ak || !sk) return { type: "failed", error: "AK 和 SK 都不能为空" }
            try {
              // statistics 校验：错误的密钥 / 未开通码道在这里被拒绝
              const res = await fetchCaStatistics(ak, sk)
              if (res.status === 401 || res.status === 403) throw new Error(`AK/SK 校验失败：HTTP ${res.status}`)
              if (res.status === 404) throw new Error("码道接口不存在；请确认该账号所在区域已开通 CodeArts（码道）")
              if (!res.ok) throw new Error(`AK/SK 校验失败：HTTP ${res.status}${res.text ? `：${res.text.slice(0, 120)}` : ""}`)
              const sub = res.json
              if (sub && typeof sub.code === "number" && sub.code !== 0) throw new Error(`AK/SK 校验失败：${caFirstOf(sub.message, sub.msg) || `code ${sub.code}`}`)
              return { type: "success", key: ak, metadata: { sk } }
            } catch (e) {
              return { type: "failed", error: redacted({ key: ak, metadata: { sk } }, e?.message ?? String(e)) }
            }
          },
        },
      ],
    },
  })
}

export const CodeArtsAkskPlugin = makeCodeartsPlugin()

// for tests
export const _internal = {
  PROVIDER, CLOUD_BASE, REGION, SCOPE_SERVICE, CPV_PATH, SUB_PATH, CLAIM_PATH,
  DEFAULT_GATEWAY, UA, MODELS, NPM,
  signSdk, signV11, canonicalRequest, canonicalUri, canonicalQuery, signedHeaders, sdkDate,
  baseUrlOf, hostOf, basicOf, credentialOf,
  fetchPermission, controlCall, subscriptionOf, claimBonus,
  vendorError, redacted, baselineOf, bonusList, gainedBetween,
  usageOf, staticModels, modelOf, liveModels,
  NO_THINKING, STRIP_WHEN_NO_THINKING, TINY_MAX_TOKENS, THINKING_ALLOWANCE,
  fitBody, aggregated, explained, gatewayFetch, EXHAUSTED, EXHAUSTED_HINT,

  // codearts
  CA_PROVIDER, CA_SNAP_HOST, CA_CHAT_API_BASE, CA_STATISTICS_URL, CA_MODELS_URL,
  CA_SESSION_LIMIT_ERROR, CA_MAX_OUTPUT_TOKENS, CA_TOOL_NAME_LIMIT, CA_TOOL_NAME_KEEP,
  CA_CREDIT_METRIC_LABELS, CA_TOTAL_CREDIT_METRIC, CA_PACKAGE_TYPE_METRICS,
  caSign, caSnapRequest, fetchCaStatistics, fetchCaBuiltinModels, fetchCaCreditBatches, caBatchesOf,
  caUsageOf, caVendorDate, caNormalizeModelId,
  caToolNameSlots, caCutToolName, caShortenToolNames, caRestoreToolNames, caRestoreToolNamesInStream,
  caFitBody, caErrorCodeOf, caErrorMessageOf, caEmbeddedErrorStatus, caPeekAnswer, caReplayBody, caFoldAnswer,
  caGatewayFetch, caModelEntry, caStaticModels, caParseBuiltin, caSessionIdOf,
  makeCodeartsPlugin,
}
