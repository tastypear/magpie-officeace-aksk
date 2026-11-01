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

import { createHmac, createHash } from "node:crypto"

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

const compact = (n) => (Number.isInteger(n) ? String(n) : n.toFixed(2).replace(/0+$/, "").replace(/\.$/, ""))

// usageOf turns a subscription answer into magpie's usage card: the credits
// of the plan's skus and of the bonuses still alive, total minus used, the
// expired entries not counted — the arithmetic credgate's calc_credits and
// OfficeAce's own picker agree on. An unlimited quota (-1) says no share,
// and is left out of the window.
function usageOf(sub, now = Date.now()) {
  const skus = Array.isArray(sub?.skus) ? sub.skus : []
  const bonus = Array.isArray(sub?.bonus_skus) ? sub.bonus_skus : []
  let total = 0, used = 0
  const dying = []
  for (const s of skus) {
    for (const q of Array.isArray(s?.quotas) ? s.quotas : []) {
      if (q?.sku_attr_code !== "officeace_points") continue
      const exp = Date.parse(q?.expired_time || "") || 0
      if (exp && exp <= now) continue
      const grant = Number(q.sku_value) || 0
      if (grant < 0) continue
      total += grant
      used += Number(q.current_value) || 0
      dying.push({ left: grant - (Number(q.current_value) || 0), exp })
    }
  }
  for (const b of bonus) {
    const exp = Date.parse(b?.expired_time || "") || 0
    if (exp && exp <= now) continue
    const grant = Number(b.points) || 0
    if (grant < 0) continue
    total += grant
    used += Number(b.current_value) || 0
    dying.push({ left: grant - (Number(b.current_value) || 0), exp })
  }
  const windows = []
  if (total > 0) {
    windows.push({
      name: "Credits",
      used: (100 * used) / total,
      display: `${compact(used)} / ${compact(total)}`,
      amount: used,
      limit: total,
      unit: "credits",
    })
    // the soonest moment credits left are lost, and how many — magpie's
    // smart routing spends the account whose credits expire first. A quota
    // that names no end ends when the plan does, so it isn't counted.
    let at = 0, amount = 0
    for (const d of dying) {
      if (!(d.left > 0) || d.exp <= now) continue
      if (!at || d.exp < at) { at = d.exp; amount = d.left }
      else if (d.exp === at) amount += d.left
    }
    if (at) Object.assign(windows[0], { runsOutAt: new Date(at).toISOString(), runsOut: amount })
  }
  const main = skus[0] || null
  const tier = String(main?.sku_code || "").split(".").pop() || ""
  const until = Date.parse(main?.expired_time || "") || 0
  return {
    plan: main?.sku_name || TIER_NAMES[tier] || (total > 0 ? "OfficeAce" : ""),
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
          placeholder: "Access Key (AK)",
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
}
