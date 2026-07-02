const CONTENT_KEY = "content/current.txt";
const CREDENTIALS_KEY = "auth/credentials.json";
const SESSION_SECRET_KEY = "auth/session-secret.txt";
const SESSION_COOKIE = "base64share_session";
const SESSION_TTL_SECONDS = 8 * 60 * 60;
const MAX_EDIT_BYTES = 10 * 1024 * 1024;
const MAX_AUTH_BODY_BYTES = 16 * 1024;
// Cloudflare's production Web Crypto runtime rejects PBKDF2 counts above 100,000.
const PASSWORD_ITERATIONS = 100_000;
const encoder = new TextEncoder();
const BASE64_ALPHABET = encoder.encode(
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
);

const SECURITY_HEADERS: Record<string, string> = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "same-origin",
};

interface Credentials {
  version: 1;
  username: string;
  passwordSalt: string;
  passwordHash: string;
  passwordIterations: number;
  updatedAt: string;
}

interface StoredCredentials {
  value: Credentials;
  etag: string;
}

export default {
  async fetch(request, env): Promise<Response> {
    const url = new URL(request.url);

    try {
      if (url.pathname === "/") {
        return request.method === "GET" || request.method === "HEAD"
          ? nginxWelcome(request.method === "HEAD")
          : methodNotAllowed("GET, HEAD");
      }

      if (url.pathname === "/admin") {
        return await handleAdmin(request, env);
      }

      if (url.pathname === "/register") {
        return await handleRegister(request, env);
      }

      if (url.pathname === "/dashboard") {
        return await handleDashboard(request, env);
      }

      if (url.pathname === "/dashboard/account") {
        return await handleAccountUpdate(request, env);
      }

      if (url.pathname === "/dashboard/session-secret/rotate") {
        return await handleSessionSecretRotation(request, env);
      }

      if (url.pathname === "/logout") {
        return await handleLogout(request, env);
      }

      if (request.method !== "GET" && request.method !== "HEAD") {
        return methodNotAllowed("GET, HEAD");
      }

      return await handlePublicPath(request, env, url.pathname);
    } catch (error) {
      if (error instanceof HttpError) {
        return Response.json(
          { error: error.message },
          { status: error.status, headers: responseHeaders({ "Cache-Control": "no-store" }) },
        );
      }
      console.error(
        JSON.stringify({
          message: "request failed",
          method: request.method,
          path: url.pathname,
          error: error instanceof Error ? error.message : String(error),
        }),
      );
      return textResponse("服务器内部错误。", 500);
    }
  },
} satisfies ExportedHandler<Env>;

async function handleAdmin(request: Request, env: Env): Promise<Response> {
  if (request.method === "GET" || request.method === "HEAD") {
    if (await hasValidSession(request, env)) {
      return redirect(new URL("/dashboard", request.url).toString());
    }
    await ensureSessionSecret(env.CONTENT_BUCKET);
    const registered = (await loadCredentials(env.CONTENT_BUCKET)) !== null;
    return htmlResponse(loginPage(registered), 200, request.method === "HEAD");
  }

  if (request.method !== "POST") {
    return methodNotAllowed("GET, HEAD, POST");
  }

  if (!isSameOrigin(request)) {
    return textResponse("请求来源无效。", 403);
  }

  const contentType = request.headers.get("Content-Type") ?? "";
  if (!contentType.toLowerCase().startsWith("application/x-www-form-urlencoded")) {
    return textResponse("登录请求格式无效。", 415);
  }

  const body = await readBoundedText(request, MAX_AUTH_BODY_BYTES);
  const form = new URLSearchParams(body);
  const username = form.get("username") ?? "";
  const password = form.get("password") ?? "";
  const stored = await loadCredentials(env.CONTENT_BUCKET);
  if (!stored) {
    return htmlResponse(loginPage(false, "尚未注册管理员账户，请先注册。"), 409);
  }
  const [usernameMatches, passwordMatches] = await Promise.all([
    secureStringEqual(username, stored.value.username),
    verifyPassword(password, stored.value),
  ]);

  if (!usernameMatches || !passwordMatches) {
    return htmlResponse(loginPage(true, "用户名或密码错误。"), 401);
  }

  const sessionSecret = await ensureSessionSecret(env.CONTENT_BUCKET);
  const token = await createSessionToken(sessionSecret);
  const headers = new Headers({ Location: new URL("/dashboard", request.url).toString() });
  headers.set("Set-Cookie", sessionCookie(token, request.url));
  addSecurityHeaders(headers);
  return new Response(null, { status: 303, headers });
}

async function handleRegister(request: Request, env: Env): Promise<Response> {
  if (request.method !== "POST") {
    return methodNotAllowed("POST");
  }
  if (!isSameOrigin(request)) {
    return textResponse("请求来源无效。", 403);
  }

  const contentType = request.headers.get("Content-Type") ?? "";
  if (!contentType.toLowerCase().startsWith("application/x-www-form-urlencoded")) {
    return textResponse("注册请求格式无效。", 415);
  }

  await ensureSessionSecret(env.CONTENT_BUCKET);
  if (await loadCredentials(env.CONTENT_BUCKET)) {
    return htmlResponse(loginPage(true, "管理员账户已经存在，不能再次注册。"), 409);
  }

  const form = new URLSearchParams(await readBoundedText(request, MAX_AUTH_BODY_BYTES));
  const username = normalizeUsername(form.get("username") ?? "");
  const password = form.get("password") ?? "";
  validateNewCredentials(username, password);
  const credentials = await createCredentials(username, password);
  const created = await env.CONTENT_BUCKET.put(
    CREDENTIALS_KEY,
    JSON.stringify(credentials),
    {
      onlyIf: new Headers({ "If-None-Match": "*" }),
      httpMetadata: { contentType: "application/json; charset=utf-8" },
    },
  );

  if (!created) {
    return htmlResponse(loginPage(true, "管理员账户已被创建，请直接登录。"), 409);
  }

  const sessionSecret = await ensureSessionSecret(env.CONTENT_BUCKET);
  const token = await createSessionToken(sessionSecret);
  const headers = new Headers({ Location: new URL("/dashboard", request.url).toString() });
  headers.set("Set-Cookie", sessionCookie(token, request.url));
  addSecurityHeaders(headers);
  return new Response(null, { status: 303, headers });
}

async function handleDashboard(request: Request, env: Env): Promise<Response> {
  if (!(await hasValidSession(request, env))) {
    return redirect(new URL("/admin", request.url).toString());
  }

  if (request.method === "GET" || request.method === "HEAD") {
    const credentials = await loadCredentials(env.CONTENT_BUCKET);
    if (!credentials) {
      return redirect(new URL("/admin", request.url).toString());
    }
    const object = await env.CONTENT_BUCKET.get(CONTENT_KEY);
    let content = "";
    let notice = "";

    if (object) {
      if (object.size <= MAX_EDIT_BYTES) {
        content = await object.text();
      } else {
        notice = "当前 R2 对象超过控制台的 10 MiB 编辑上限，请先通过 R2 工具替换或删除。";
      }
    }

    const info = {
      exists: object !== null,
      size: object?.size ?? 0,
      updatedAt: object?.customMetadata?.updatedAt ?? object?.uploaded.toISOString() ?? "尚未保存",
    };
    return htmlResponse(
      dashboardPage(content, info, notice, credentials.value.username),
      200,
      request.method === "HEAD",
    );
  }

  if (request.method !== "POST") {
    return methodNotAllowed("GET, HEAD, POST");
  }

  if (!isSameOrigin(request)) {
    return textResponse("请求来源无效。", 403);
  }

  const contentType = request.headers.get("Content-Type") ?? "";
  if (!contentType.toLowerCase().startsWith("text/plain")) {
    return textResponse("保存请求必须使用 text/plain。", 415);
  }

  const content = await readBoundedText(request, MAX_EDIT_BYTES);
  const updatedAt = new Date().toISOString();
  await env.CONTENT_BUCKET.put(CONTENT_KEY, content, {
    httpMetadata: { contentType: "text/plain; charset=utf-8" },
    customMetadata: { updatedAt },
  });

  return Response.json(
    { ok: true, bytes: encoder.encode(content).byteLength, updatedAt },
    { headers: responseHeaders({ "Cache-Control": "no-store" }) },
  );
}

async function handleAccountUpdate(request: Request, env: Env): Promise<Response> {
  if (!(await hasValidSession(request, env))) {
    return Response.json(
      { error: "登录状态已失效，请重新登录。" },
      { status: 401, headers: responseHeaders({ "Cache-Control": "no-store" }) },
    );
  }
  if (request.method !== "POST") {
    return methodNotAllowed("POST");
  }
  if (!isSameOrigin(request)) {
    return textResponse("请求来源无效。", 403);
  }

  const contentType = request.headers.get("Content-Type") ?? "";
  if (!contentType.toLowerCase().startsWith("application/x-www-form-urlencoded")) {
    return textResponse("账户修改请求格式无效。", 415);
  }

  const stored = await loadCredentials(env.CONTENT_BUCKET);
  if (!stored) {
    throw new HttpError(409, "管理员账户不存在，请重新注册。");
  }

  const form = new URLSearchParams(await readBoundedText(request, MAX_AUTH_BODY_BYTES));
  const username = normalizeUsername(form.get("username") ?? "");
  const newPassword = form.get("password") ?? "";
  validateUsername(username);

  const updated = newPassword
    ? await createCredentials(username, newPassword)
    : { ...stored.value, username, updatedAt: new Date().toISOString() };
  const saved = await env.CONTENT_BUCKET.put(CREDENTIALS_KEY, JSON.stringify(updated), {
    onlyIf: { etagMatches: stored.etag },
    httpMetadata: { contentType: "application/json; charset=utf-8" },
  });
  if (!saved) {
    throw new HttpError(409, "账户信息已被其他请求修改，请刷新后重试。");
  }

  const sessionSecret = await rotateSessionSecret(env.CONTENT_BUCKET);
  const token = await createSessionToken(sessionSecret);
  const headers = responseHeaders({ "Cache-Control": "no-store" });
  headers.set("Set-Cookie", sessionCookie(token, request.url));
  return Response.json(
    { ok: true, username: updated.username, updatedAt: updated.updatedAt },
    { headers },
  );
}

async function handleSessionSecretRotation(request: Request, env: Env): Promise<Response> {
  if (!(await hasValidSession(request, env))) {
    return Response.json(
      { error: "登录状态已失效，请重新登录。" },
      { status: 401, headers: responseHeaders({ "Cache-Control": "no-store" }) },
    );
  }
  if (request.method !== "POST") {
    return methodNotAllowed("POST");
  }
  if (!isSameOrigin(request)) {
    return textResponse("请求来源无效。", 403);
  }

  const sessionSecret = await rotateSessionSecret(env.CONTENT_BUCKET);
  const token = await createSessionToken(sessionSecret);
  const rotatedAt = new Date().toISOString();
  const headers = responseHeaders({ "Cache-Control": "no-store" });
  headers.set("Set-Cookie", sessionCookie(token, request.url));
  return Response.json({ ok: true, rotatedAt }, { headers });
}

async function handleLogout(request: Request, env: Env): Promise<Response> {
  if (request.method !== "POST") {
    return methodNotAllowed("POST");
  }
  if (!isSameOrigin(request)) {
    return textResponse("请求来源无效。", 403);
  }

  // Evaluate the session before clearing it so malformed tokens follow the same path.
  await hasValidSession(request, env);
  const headers = new Headers({ Location: new URL("/admin", request.url).toString() });
  headers.set("Set-Cookie", expiredSessionCookie(request.url));
  addSecurityHeaders(headers);
  return new Response(null, { status: 303, headers });
}

async function handlePublicPath(
  request: Request,
  env: Env,
  pathname: string,
): Promise<Response> {
  let decodedPath: string;
  try {
    decodedPath = decodeURIComponent(pathname.slice(1));
  } catch {
    return textResponse("错误：路径包含无效的百分号编码。", 400);
  }

  if ([...decodedPath].length <= 10) {
    return textResponse("错误：路径字符长度不够，必须超过 10 个字符。", 400);
  }

  if (request.method === "HEAD") {
    const object = await env.CONTENT_BUCKET.head(CONTENT_KEY);
    const headers = responseHeaders({
      "Content-Type": "text/plain; charset=utf-8",
      "Cache-Control": "no-store",
    });
    if (object) {
      headers.set("Content-Length", String(4 * Math.ceil(object.size / 3)));
    }
    return new Response(null, { status: 200, headers });
  }

  const object = await env.CONTENT_BUCKET.get(CONTENT_KEY);
  if (!object) {
    return textResponse("", 200);
  }

  const encoded = object.body.pipeThrough(createBase64Transform());
  return new Response(encoded, {
    status: 200,
    headers: responseHeaders({
      "Content-Type": "text/plain; charset=utf-8",
      "Cache-Control": "no-store",
    }),
  });
}

function createBase64Transform(): TransformStream<Uint8Array, Uint8Array> {
  let remainder = new Uint8Array(0);

  return new TransformStream<Uint8Array, Uint8Array>({
    transform(chunk, controller): void {
      const input = new Uint8Array(remainder.byteLength + chunk.byteLength);
      input.set(remainder);
      input.set(chunk, remainder.byteLength);

      const completeLength = input.byteLength - (input.byteLength % 3);
      if (completeLength > 0) {
        controller.enqueue(encodeBase64(input.subarray(0, completeLength), false));
      }
      remainder = input.slice(completeLength);
    },
    flush(controller): void {
      if (remainder.byteLength > 0) {
        controller.enqueue(encodeBase64(remainder, true));
      }
    },
  });
}

function encodeBase64(input: Uint8Array, pad: boolean): Uint8Array {
  const outputLength = pad ? 4 * Math.ceil(input.byteLength / 3) : (input.byteLength / 3) * 4;
  const output = new Uint8Array(outputLength);
  let source = 0;
  let target = 0;

  while (source + 2 < input.byteLength) {
    const value = (input[source] << 16) | (input[source + 1] << 8) | input[source + 2];
    output[target++] = BASE64_ALPHABET[(value >>> 18) & 63];
    output[target++] = BASE64_ALPHABET[(value >>> 12) & 63];
    output[target++] = BASE64_ALPHABET[(value >>> 6) & 63];
    output[target++] = BASE64_ALPHABET[value & 63];
    source += 3;
  }

  const remaining = input.byteLength - source;
  if (remaining === 1) {
    const value = input[source] << 16;
    output[target++] = BASE64_ALPHABET[(value >>> 18) & 63];
    output[target++] = BASE64_ALPHABET[(value >>> 12) & 63];
    output[target++] = 61;
    output[target] = 61;
  } else if (remaining === 2) {
    const value = (input[source] << 16) | (input[source + 1] << 8);
    output[target++] = BASE64_ALPHABET[(value >>> 18) & 63];
    output[target++] = BASE64_ALPHABET[(value >>> 12) & 63];
    output[target++] = BASE64_ALPHABET[(value >>> 6) & 63];
    output[target] = 61;
  }

  return output;
}

async function readBoundedText(request: Request, maxBytes: number): Promise<string> {
  const declaredLength = Number(request.headers.get("Content-Length") ?? "0");
  if (Number.isFinite(declaredLength) && declaredLength > maxBytes) {
    throw new HttpError(413, `文本不能超过 ${formatBytes(maxBytes)}。`);
  }
  if (!request.body) {
    return "";
  }

  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;

  while (true) {
    const result = await reader.read();
    if (result.done) break;
    total += result.value.byteLength;
    if (total > maxBytes) {
      await reader.cancel("body too large");
      throw new HttpError(413, `文本不能超过 ${formatBytes(maxBytes)}。`);
    }
    chunks.push(result.value);
  }

  const combined = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    combined.set(chunk, offset);
    offset += chunk.byteLength;
  }

  try {
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(combined);
  } catch {
    throw new HttpError(400, "请求正文不是有效的 UTF-8 文本。");
  }
}

async function secureStringEqual(provided: string, expected: string): Promise<boolean> {
  const [providedHash, expectedHash] = await Promise.all([
    crypto.subtle.digest("SHA-256", encoder.encode(provided)),
    crypto.subtle.digest("SHA-256", encoder.encode(expected)),
  ]);
  return crypto.subtle.timingSafeEqual(providedHash, expectedHash);
}

async function createCredentials(username: string, password: string): Promise<Credentials> {
  validateNewCredentials(username, password);
  const salt = randomBytes(16);
  const hash = await derivePasswordHash(password, salt, PASSWORD_ITERATIONS);
  return {
    version: 1,
    username,
    passwordSalt: base64Url(salt),
    passwordHash: base64Url(hash),
    passwordIterations: PASSWORD_ITERATIONS,
    updatedAt: new Date().toISOString(),
  };
}

async function verifyPassword(password: string, credentials: Credentials): Promise<boolean> {
  try {
    const salt = fromBase64Url(credentials.passwordSalt);
    const expected = fromBase64Url(credentials.passwordHash);
    const provided = await derivePasswordHash(
      password,
      salt,
      credentials.passwordIterations,
    );
    return crypto.subtle.timingSafeEqual(provided, expected);
  } catch {
    return false;
  }
}

async function derivePasswordHash(
  password: string,
  salt: Uint8Array,
  iterations: number,
): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, [
    "deriveBits",
  ]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations },
    key,
    256,
  );
  return new Uint8Array(bits);
}

async function loadCredentials(bucket: R2Bucket): Promise<StoredCredentials | null> {
  const object = await bucket.get(CREDENTIALS_KEY);
  if (!object) return null;
  if (object.size > MAX_AUTH_BODY_BYTES) {
    throw new HttpError(500, "R2 中的账户配置体积异常。请检查 auth/credentials.json。 ");
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(await object.text());
  } catch {
    throw new HttpError(500, "R2 中的账户配置不是有效 JSON。");
  }
  if (!isCredentials(parsed)) {
    throw new HttpError(500, "R2 中的账户配置格式无效。");
  }
  return { value: parsed, etag: object.etag };
}

function isCredentials(value: unknown): value is Credentials {
  if (typeof value !== "object" || value === null) return false;
  const record = value as Record<string, unknown>;
  return (
    record.version === 1 &&
    typeof record.username === "string" &&
    typeof record.passwordSalt === "string" &&
    /^[A-Za-z0-9_-]+$/u.test(record.passwordSalt) &&
    typeof record.passwordHash === "string" &&
    /^[A-Za-z0-9_-]+$/u.test(record.passwordHash) &&
    typeof record.passwordIterations === "number" &&
    Number.isSafeInteger(record.passwordIterations) &&
    record.passwordIterations >= 100_000 &&
    record.passwordIterations <= PASSWORD_ITERATIONS &&
    typeof record.updatedAt === "string"
  );
}

async function ensureSessionSecret(bucket: R2Bucket): Promise<string> {
  const existing = await bucket.get(SESSION_SECRET_KEY);
  if (existing) return readSessionSecret(await existing.text());

  const generated = base64Url(randomBytes(32));
  const created = await bucket.put(SESSION_SECRET_KEY, generated, {
    onlyIf: new Headers({ "If-None-Match": "*" }),
    httpMetadata: { contentType: "text/plain; charset=utf-8" },
  });
  if (created) return generated;

  const winner = await bucket.get(SESSION_SECRET_KEY);
  if (!winner) throw new HttpError(500, "自动创建会话密钥失败，请重试。");
  return readSessionSecret(await winner.text());
}

async function rotateSessionSecret(bucket: R2Bucket): Promise<string> {
  const generated = base64Url(randomBytes(32));
  await bucket.put(SESSION_SECRET_KEY, generated, {
    httpMetadata: { contentType: "text/plain; charset=utf-8" },
  });
  return generated;
}

function readSessionSecret(value: string): string {
  if (!/^[A-Za-z0-9_-]{43}$/u.test(value)) {
    throw new HttpError(500, "R2 中的会话密钥格式无效。删除该对象后可自动重新生成。");
  }
  return value;
}

function randomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

function normalizeUsername(value: string): string {
  return value.trim();
}

function validateNewCredentials(username: string, password: string): void {
  validateUsername(username);
  const passwordLength = [...password].length;
  if (passwordLength < 8 || passwordLength > 1024) {
    throw new HttpError(400, "密码长度必须为 8 到 1024 个字符。");
  }
}

function validateUsername(username: string): void {
  const length = [...username].length;
  if (length < 1 || length > 100 || /[\u0000-\u001F\u007F]/u.test(username)) {
    throw new HttpError(400, "用户名必须为 1 到 100 个可显示字符。");
  }
}

async function createSessionToken(secret: string): Promise<string> {
  const expiresAt = Math.floor(Date.now() / 1000) + SESSION_TTL_SECONDS;
  const nonce = new Uint8Array(16);
  crypto.getRandomValues(nonce);
  const payload = `v1.${expiresAt}.${base64Url(nonce)}`;
  const signature = await sign(payload, secret);
  return `${payload}.${base64Url(signature)}`;
}

async function hasValidSession(request: Request, env: Env): Promise<boolean> {
  const token = readCookie(request.headers.get("Cookie"), SESSION_COOKIE);
  if (!token) return false;

  const parts = token.split(".");
  if (parts.length !== 4 || parts[0] !== "v1") return false;
  const expiresAt = Number(parts[1]);
  if (!Number.isSafeInteger(expiresAt) || expiresAt < Math.floor(Date.now() / 1000)) {
    return false;
  }

  let providedSignature: Uint8Array;
  try {
    providedSignature = fromBase64Url(parts[3]);
  } catch {
    return false;
  }
  const sessionSecret = await ensureSessionSecret(env.CONTENT_BUCKET);
  const expectedSignature = await sign(parts.slice(0, 3).join("."), sessionSecret);
  if (providedSignature.byteLength !== expectedSignature.byteLength) return false;
  return crypto.subtle.timingSafeEqual(providedSignature, expectedSignature);
}

async function sign(payload: string, secret: string): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, encoder.encode(payload)));
}

function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

function fromBase64Url(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/u.test(value)) throw new Error("invalid base64url");
  const padded = value.replaceAll("-", "+").replaceAll("_", "/").padEnd(
    Math.ceil(value.length / 4) * 4,
    "=",
  );
  return Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
}

function readCookie(header: string | null, name: string): string | null {
  if (!header) return null;
  for (const pair of header.split(";")) {
    const separator = pair.indexOf("=");
    if (separator < 0) continue;
    if (pair.slice(0, separator).trim() === name) {
      return pair.slice(separator + 1).trim();
    }
  }
  return null;
}

function sessionCookie(token: string, requestUrl: string): string {
  const secure = new URL(requestUrl).protocol === "https:" ? "; Secure" : "";
  return `${SESSION_COOKIE}=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${SESSION_TTL_SECONDS}${secure}`;
}

function expiredSessionCookie(requestUrl: string): string {
  const secure = new URL(requestUrl).protocol === "https:" ? "; Secure" : "";
  return `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${secure}`;
}

function isSameOrigin(request: Request): boolean {
  const expected = new URL(request.url).origin;
  const origin = request.headers.get("Origin");
  if (origin) return origin === expected;

  const referer = request.headers.get("Referer");
  if (referer) {
    try {
      return new URL(referer).origin === expected;
    } catch {
      return false;
    }
  }

  // Some browsers omit Origin on local form submissions. Sec-Fetch-Site is a
  // browser-controlled header and provides a safe same-origin fallback.
  return request.headers.get("Sec-Fetch-Site") === "same-origin";
}

class HttpError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

function nginxWelcome(headOnly: boolean): Response {
  const html = `<!DOCTYPE html>
<html><head><title>Welcome to nginx!</title><style>
html { color-scheme: light; } body { width: 35em; margin: 0 auto; font-family: Tahoma, Verdana, Arial, sans-serif; }
</style></head><body><h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and working. Further configuration is required.</p>
<p>For online documentation and support please refer to <a href="https://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at <a href="https://nginx.com/">nginx.com</a>.</p>
<p><em>Thank you for using nginx.</em></p></body></html>`;
  const headers = responseHeaders({ "Content-Type": "text/html; charset=utf-8" });
  return new Response(headOnly ? null : html, { status: 200, headers });
}

function loginPage(registered: boolean, error = ""): string {
  const nonce = crypto.randomUUID();
  return pageShell(
    "管理员登录",
    `<main class="card"><h1>管理员登录</h1><p class="sub">${registered ? "登录后可修改分享文本和账户信息。" : "尚未注册。请输入用户名和密码，然后点击注册；会话密钥已自动保存在 R2。"}</p>
    ${error ? `<div class="error" role="alert">${escapeHtml(error)}</div>` : ""}
    <form method="post" action="/admin">
      <label>用户名<input name="username" autocomplete="username" required autofocus></label>
      <label>密码<input name="password" type="password" autocomplete="${registered ? "current-password" : "new-password"}"${registered ? "" : " minlength=\"8\""} required></label>
      <div class="actions"><button type="submit">登录</button>${registered ? "" : "<button class=\"secondary\" type=\"submit\" formaction=\"/register\">注册</button>"}</div>
    </form></main>`,
    nonce,
  );
}

function dashboardPage(
  content: string,
  info: { exists: boolean; size: number; updatedAt: string },
  notice: string,
  username: string,
): string {
  const nonce = crypto.randomUUID();
  const disabled = notice ? " disabled" : "";
  const body = `<main class="wide card">
    <div class="top"><div><h1>文本控制台</h1><p class="sub">内容保存在 R2 的 <code>${CONTENT_KEY}</code></p></div>
    <form method="post" action="/logout"><button class="secondary" type="submit">退出</button></form></div>
    ${notice ? `<div class="error" role="alert">${escapeHtml(notice)}</div>` : ""}
    <dl><div><dt>状态</dt><dd>${info.exists ? "已保存" : "尚未保存"}</dd></div><div><dt>大小</dt><dd id="size">${formatBytes(info.size)}</dd></div><div><dt>更新时间</dt><dd id="updated">${escapeHtml(info.updatedAt)}</dd></div></dl>
    <label for="content">分享文本</label>
    <textarea id="content" spellcheck="false"${disabled}>${escapeHtml(content)}</textarea>
    <div class="actions"><span id="status" aria-live="polite"></span><button id="save" type="button"${disabled}>保存文本</button></div>
    <section class="account"><h2>管理员账户</h2><p class="sub">修改后会自动退出其他已登录会话。密码留空表示不修改。</p>
      <form id="account-form" action="/dashboard/account" method="post">
        <label>用户名<input id="account-username" name="username" value="${escapeHtml(username)}" autocomplete="username" required maxlength="100"></label>
        <label>新密码<input name="password" type="password" autocomplete="new-password" minlength="8" placeholder="留空则保持原密码"></label>
        <div class="actions"><span id="account-status" aria-live="polite"></span><button id="account-save" type="submit">保存账户信息</button></div>
      </form>
    </section>
    <section class="account"><h2>会话密钥</h2><p class="sub">主动生成新的会话签名密钥。轮换后，除当前浏览器外的所有登录会话都会失效。</p>
      <div class="actions"><span id="rotate-status" aria-live="polite"></span><button id="rotate-secret" class="secondary" type="button">轮换会话密钥</button></div>
    </section>
  </main>
  <script nonce="${nonce}">
  const button = document.getElementById('save');
  const area = document.getElementById('content');
  const status = document.getElementById('status');
  if (button && area && status) button.addEventListener('click', async () => {
    button.disabled = true; status.textContent = '正在保存…';
    try {
      const response = await fetch('/dashboard', { method: 'POST', headers: { 'Content-Type': 'text/plain; charset=utf-8' }, body: area.value });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || '保存失败');
      document.getElementById('size').textContent = formatBytes(data.bytes);
      document.getElementById('updated').textContent = data.updatedAt;
      status.textContent = '保存成功';
    } catch (error) { status.textContent = error instanceof Error ? error.message : '保存失败'; }
    finally { button.disabled = false; }
  });
  const accountForm = document.getElementById('account-form');
  const accountButton = document.getElementById('account-save');
  const accountStatus = document.getElementById('account-status');
  if (accountForm && accountButton && accountStatus) accountForm.addEventListener('submit', async (event) => {
    event.preventDefault(); accountButton.disabled = true; accountStatus.textContent = '正在保存…';
    try {
      const response = await fetch('/dashboard/account', { method: 'POST', body: new URLSearchParams(new FormData(accountForm)) });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || '账户信息保存失败');
      accountForm.elements.password.value = '';
      accountStatus.textContent = '账户信息已保存';
    } catch (error) { accountStatus.textContent = error instanceof Error ? error.message : '账户信息保存失败'; }
    finally { accountButton.disabled = false; }
  });
  const rotateButton = document.getElementById('rotate-secret');
  const rotateStatus = document.getElementById('rotate-status');
  if (rotateButton && rotateStatus) rotateButton.addEventListener('click', async () => {
    if (!confirm('轮换后，其他所有已登录会话都会失效。确定继续吗？')) return;
    rotateButton.disabled = true; rotateStatus.textContent = '正在轮换…';
    try {
      const response = await fetch('/dashboard/session-secret/rotate', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || '密钥轮换失败');
      rotateStatus.textContent = '密钥已轮换';
    } catch (error) { rotateStatus.textContent = error instanceof Error ? error.message : '密钥轮换失败'; }
    finally { rotateButton.disabled = false; }
  });
  function formatBytes(bytes) { if (bytes < 1024) return bytes + ' B'; if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KiB'; return (bytes / 1048576).toFixed(2) + ' MiB'; }
  </script>`;
  return pageShell("文本控制台", body, nonce);
}

function pageShell(title: string, body: string, nonce: string): string {
  return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>${escapeHtml(title)}</title><style nonce="${nonce}">
  :root{font-family:Inter,"PingFang SC","Microsoft YaHei",sans-serif;color:#172033;background:#f3f6fb}*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px}.card{width:min(420px,100%);background:#fff;border:1px solid #dfe5ef;border-radius:16px;padding:28px;box-shadow:0 16px 50px #23406b17}.wide{width:min(900px,100%)}h1{margin:0 0 6px;font-size:26px}h2{margin:0 0 6px;font-size:20px}.sub{color:#697386;margin:0 0 24px}label{display:grid;gap:7px;font-weight:600;margin:16px 0}input,textarea{width:100%;border:1px solid #cbd4e1;border-radius:9px;padding:11px 12px;font:inherit;background:#fff}input:focus,textarea:focus{outline:3px solid #3b82f633;border-color:#3b82f6}textarea{min-height:360px;resize:vertical;font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:14px;line-height:1.55}button{border:0;border-radius:9px;background:#2563eb;color:#fff;padding:11px 18px;font:inherit;font-weight:700;cursor:pointer}button:disabled{opacity:.55;cursor:not-allowed}.secondary{background:#e8edf5;color:#263246}.error{background:#fff0f0;color:#a11919;border:1px solid #ffd1d1;border-radius:9px;padding:11px 13px;margin:16px 0}.top,.actions{display:flex;align-items:center;justify-content:space-between;gap:16px}.top form{margin:0}.actions{margin-top:14px}.actions span{color:#41516a}.account{border-top:1px solid #dfe5ef;margin-top:30px;padding-top:24px}dl{display:flex;gap:12px;flex-wrap:wrap;margin:20px 0}dl div{background:#f3f6fb;border-radius:9px;padding:10px 13px;min-width:130px}dt{color:#697386;font-size:12px}dd{margin:4px 0 0;font-weight:700;overflow-wrap:anywhere}code{font-size:.9em}@media(max-width:600px){.card{padding:20px}.top{align-items:flex-start}textarea{min-height:50vh}}
  </style></head><body>${body}</body></html>`;
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/gu, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  })[character] ?? character);
}

function htmlResponse(html: string, status: number, headOnly = false): Response {
  const nonceMatch = html.match(/nonce="([^"]+)"/u);
  const headers = responseHeaders({
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-store",
    "Content-Security-Policy": `default-src 'none'; connect-src 'self'; style-src 'nonce-${nonceMatch?.[1] ?? "none"}'; script-src 'nonce-${nonceMatch?.[1] ?? "none"}'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'`,
  });
  return new Response(headOnly ? null : html, { status, headers });
}

function textResponse(body: string, status: number): Response {
  return new Response(body, {
    status,
    headers: responseHeaders({
      "Content-Type": "text/plain; charset=utf-8",
      "Cache-Control": "no-store",
    }),
  });
}

function methodNotAllowed(allow: string): Response {
  const response = textResponse("Method Not Allowed", 405);
  response.headers.set("Allow", allow);
  return response;
}

function redirect(location: string): Response {
  return new Response(null, { status: 303, headers: responseHeaders({ Location: location }) });
}

function responseHeaders(initial: HeadersInit = {}): Headers {
  const headers = new Headers(initial);
  addSecurityHeaders(headers);
  return headers;
}

function addSecurityHeaders(headers: Headers): void {
  for (const [name, value] of Object.entries(SECURITY_HEADERS)) headers.set(name, value);
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${(bytes / 1024 / 1024).toFixed(2)} MiB`;
}
