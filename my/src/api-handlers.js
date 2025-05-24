import { jsonResponse, hashPassword, constantTimeCompare, generateSessionId, generateTotpSecret, verifyTotp, EXTERNAL_PASTE_API_BASE_URL, isValidEmail, isAdminUser } from './helpers.js';
import { verifyTurnstileToken } from './turnstile-handler.js';
export async function authenticateApiRequest(sessionId, env) {
if (!sessionId || !env.DB) {
return null;
}
try {
const sessionStmt = env.DB.prepare("SELECT user_email, expires_at FROM sessions WHERE session_id = ?");
const sessionResult = await sessionStmt.bind(sessionId).first();
const nowSeconds = Math.floor(Date.now() / 1000);
if (sessionResult && sessionResult.expires_at > nowSeconds) {
return sessionResult.user_email;
} else if (sessionResult) {
} else {
}
} catch (dbError) {
}
return null;
}
async function getPasteApiBearerToken(env) {
const token = env.PASTE_API_BEARER_TOKEN;
if (!token) {
throw new Error("External API authentication token is not configured.");
}
return token;
}
export async function handleGetMe(request, env, userEmailFromSession) {
if (!userEmailFromSession) return jsonResponse({ error: '用户未认证' }, 401);
if (!env.DB) return jsonResponse({ error: '服务器配置错误 (DB_NOT_CONFIGURED)' }, 500);
const userDetailsStmt = env.DB.prepare("SELECT email, username, phone_number, two_factor_enabled FROM users WHERE email = ?");
const user = await userDetailsStmt.bind(userEmailFromSession).first();
if (!user) return jsonResponse({ error: '用户未找到' }, 404);
const adminCheck = isAdminUser(userEmailFromSession, env);
return jsonResponse({ ...user, is_admin: adminCheck });
}
export async function handleRegister(request, env, clientIp) {
try {
const reqBody = await request.json();
const { email, username, password, confirmPassword, phoneNumber, turnstileToken } = reqBody;
const turnstileVerification = await verifyTurnstileToken(turnstileToken, env.TURNSTILE_SECRET_KEY, clientIp);
if (!turnstileVerification.success) {
return jsonResponse({ error: turnstileVerification.error || '人机验证失败', details: turnstileVerification['error-codes'] }, 403);
}
if (!email || !isValidEmail(email)) return jsonResponse({ error: '需要有效的邮箱地址' }, 400);
if (!username || username.length < 3 || username.length > 30 || !/^[a-zA-Z0-9_-]+$/.test(username)) return jsonResponse({ error: '用户名必须为3-30位，可包含字母、数字、下划线和连字符' }, 400);
if (!password || password.length < 6) return jsonResponse({ error: '密码至少需要6个字符' }, 400);
if (password !== confirmPassword) return jsonResponse({ error: '两次输入的密码不一致' }, 400);
if (phoneNumber && phoneNumber.trim() !== '' && !/^\+?[0-9\s-]{7,20}$/.test(phoneNumber)) return jsonResponse({ error: '手机号码格式无效' }, 400);
if (!env.DB) return jsonResponse({ error: '服务器配置错误 (DB_NOT_CONFIGURED)' }, 500);
const batchStmts = [
env.DB.prepare("SELECT email FROM users WHERE email = ?").bind(email),
env.DB.prepare("SELECT username FROM users WHERE username = ?").bind(username)
];
const [emailExists, usernameExists] = await env.DB.batch(batchStmts);
if (emailExists.results.length > 0) return jsonResponse({ error: '该邮箱已被注册' }, 409);
if (usernameExists.results.length > 0) return jsonResponse({ error: '该用户名已被占用' }, 409);
const hashedPassword = await hashPassword(password);
const stmt = env.DB.prepare('INSERT INTO users (email, username, password_hash, phone_number, is_active, created_at) VALUES (?, ?, ?, ?, 1, ?)');
await stmt.bind(email, username, hashedPassword, phoneNumber && phoneNumber.trim() !== '' ? phoneNumber.trim() : null, Math.floor(Date.now()/1000)).run();
return jsonResponse({ success: true, message: '用户注册成功' }, 201);
} catch (e) {
if (e instanceof SyntaxError) return jsonResponse({ error: '无效的 JSON 请求体' }, 400);
const errorMsg = e.cause?.message || e.message || "未知数据库错误";
if (errorMsg.includes("UNIQUE constraint failed")) return jsonResponse({ error: '邮箱或用户名已存在 (DB)' }, 409);
return jsonResponse({ error: `注册时数据库发生错误: ${errorMsg}` }, 500);
}
}
export async function createSessionAndSetCookie(env, email, userAgent, protocol, hostname) {
const sessionId = await generateSessionId();
const nowSeconds = Math.floor(Date.now() / 1000);
const expirationSeconds = nowSeconds + (60 * 60 * 24);
try {
const sessionStmt = env.DB.prepare("INSERT INTO sessions (session_id, user_email, user_agent, created_at, expires_at) VALUES (?, ?, ?, ?, ?)");
await sessionStmt.bind(sessionId, email, userAgent, nowSeconds, expirationSeconds).run();
} catch (dbError) {
return jsonResponse({ error: `无法创建会话: ${dbError.message || '未知数据库错误'}` }, 500);
}
const cookieDomain = (hostname === 'localhost' || hostname.endsWith('.workers.dev') || hostname.endsWith('pages.dev')) ? '' : `Domain=${hostname}; `;
let cookieFlags = `${cookieDomain}Path=/; Max-Age=${60 * 60 * 24}; HttpOnly; SameSite=Strict`;
if (protocol === 'https:') cookieFlags += '; Secure';
const cookieValue = `AuthToken=${sessionId}; ${cookieFlags}`;
return new Response(JSON.stringify({ success: true, message: '登录成功' }), {
status: 200,
headers: { 'Content-Type': 'application/json;charset=UTF-8', 'Set-Cookie': cookieValue }
});
}
export async function handleLogin(request, env, protocol, hostname, clientIp) {
try {
const reqBody = await request.json();
const { identifier, password, turnstileToken } = reqBody;
const turnstileVerification = await verifyTurnstileToken(turnstileToken, env.TURNSTILE_SECRET_KEY, clientIp);
if (!turnstileVerification.success) {
return jsonResponse({ error: turnstileVerification.error || '人机验证失败', details: turnstileVerification['error-codes'] }, 403);
}
const userAgent = request.headers.get('User-Agent') || 'Unknown';
if (!identifier || !password) return jsonResponse({ error: '邮箱/用户名和密码不能为空' }, 400);
if (!env.DB) return jsonResponse({ error: '服务器配置错误 (DB_NOT_CONFIGURED)' }, 500);
const userStmt = env.DB.prepare('SELECT email, username, password_hash, two_factor_enabled, two_factor_secret, is_active FROM users WHERE email = ? OR username = ?');
const userResult = await userStmt.bind(identifier, identifier).first();
if (!userResult) return jsonResponse({ error: '邮箱/用户名或密码无效' }, 401);
if (!userResult.is_active) return jsonResponse({ error: '您的账户已被禁用，请联系管理员。' }, 403);
const passwordsMatch = await constantTimeCompare(userResult.password_hash, await hashPassword(password));
if (!passwordsMatch) return jsonResponse({ error: '邮箱/用户名或密码无效' }, 401);
if (userResult.two_factor_enabled && userResult.two_factor_secret) {
return jsonResponse({ success: true, twoFactorRequired: true, email: userResult.email });
}
return createSessionAndSetCookie(env, userResult.email, userAgent, protocol, hostname);
} catch (e) {
if (e instanceof SyntaxError) return jsonResponse({ error: '无效的 JSON 请求体' }, 400);
const errorMessage = e.message || '未知错误';
return jsonResponse({ error: `处理登录请求时发生内部错误: ${errorMessage}` }, 500);
}
}
export async function handleLogin2FAVerify(request, env, protocol, hostname) {
try {
const reqBody = await request.json();
const { email, totpCode } = reqBody;
const userAgent = request.headers.get('User-Agent') || 'Unknown';
if (!email || !totpCode) return jsonResponse({ error: '需要邮箱和两步验证码' }, 400);
if (!env.DB) return jsonResponse({ error: '服务器配置错误' }, 500);
const userStmt = env.DB.prepare('SELECT email, two_factor_secret, two_factor_enabled, is_active FROM users WHERE email = ?');
const userResult = await userStmt.bind(email).first();
if (!userResult || !userResult.two_factor_enabled || !userResult.two_factor_secret) {
return jsonResponse({ error: '用户未找到或未启用两步验证' }, 401);
}
if (!userResult.is_active) return jsonResponse({ error: '您的账户已被禁用，请联系管理员。' }, 403);
const isTotpValid = await verifyTotp(userResult.two_factor_secret, totpCode);
if (!isTotpValid) return jsonResponse({ error: '两步验证码无效' }, 401);
return createSessionAndSetCookie(env, userResult.email, userAgent, protocol, hostname);
} catch (e) {
if (e instanceof SyntaxError) return jsonResponse({ error: '无效的 JSON 请求体' }, 400);
const errorMessage = e.message || '未知错误';
return jsonResponse({ error: `处理两步验证登录时出错: ${errorMessage}` }, 500);
}
}
export async function handleChangePassword(request, env, authenticatedUserEmail) {
if (!authenticatedUserEmail) return jsonResponse({ error: '用户未认证' }, 401);
try {
const reqBody = await request.json();
const { currentPassword, newPassword } = reqBody;
if (!currentPassword || !newPassword || newPassword.length < 6) return jsonResponse({ error: '当前密码和新密码（至少6位）都是必需的' }, 400);
if (!env.DB) return jsonResponse({ error: '服务器配置错误' }, 500);
const userStmt = env.DB.prepare('SELECT password_hash FROM users WHERE email = ?');
const userResult = await userStmt.bind(authenticatedUserEmail).first();
if (!userResult) return jsonResponse({ error: '用户不存在或认证错误' }, 404);
if (!await constantTimeCompare(userResult.password_hash, await hashPassword(currentPassword))) return jsonResponse({ error: '当前密码不正确' }, 401);
const hashedNewPassword = await hashPassword(newPassword);
const updateStmt = env.DB.prepare('UPDATE users SET password_hash = ? WHERE email = ?');
await updateStmt.bind(hashedNewPassword, authenticatedUserEmail).run();
const deleteSessionsStmt = env.DB.prepare("DELETE FROM sessions WHERE user_email = ?");
await deleteSessionsStmt.bind(authenticatedUserEmail).run();
return jsonResponse({ success: true, message: '密码修改成功，所有旧会话已失效' });
} catch (e) {
if (e instanceof SyntaxError) return jsonResponse({ error: '无效的 JSON 请求体' }, 400);
const errorMessage = e.message || '未知错误';
return jsonResponse({ error: `修改密码时发生错误: ${errorMessage}` }, 500);
}
}
export async function handleUpdateProfile(request, env, authenticatedUserEmail) {
if (!authenticatedUserEmail) return jsonResponse({ error: '用户未认证' }, 401);
try {
const reqBody = await request.json();
const { username, phoneNumber } = reqBody;
if (!env.DB) return jsonResponse({ error: '服务器配置错误' }, 500);
const currentUserStmt = env.DB.prepare("SELECT username, phone_number FROM users WHERE email = ?");
const currentUser = await currentUserStmt.bind(authenticatedUserEmail).first();
if (!currentUser) return jsonResponse({ error: '用户未找到' }, 404);
const updates = [];
const bindings = [];
if (username !== undefined && username !== currentUser.username) {
if (username.length < 3 || username.length > 30 || !/^[a-zA-Z0-9_-]+$/.test(username)) return jsonResponse({ error: '用户名必须为3-30位，可包含字母、数字、下划线和连字符' }, 400);
const usernameExistsStmt = env.DB.prepare("SELECT username FROM users WHERE username = ? AND email != ?");
const usernameExists = await usernameExistsStmt.bind(username, authenticatedUserEmail).first();
if (usernameExists) return jsonResponse({ error: '该用户名已被占用' }, 409);
updates.push("username = ?");
bindings.push(username);
}
const newPhoneNumber = (phoneNumber && phoneNumber.trim() !== '') ? phoneNumber.trim() : null;
if (newPhoneNumber !== currentUser.phone_number) {
if (newPhoneNumber && !/^\+?[0-9\s-]{7,20}$/.test(newPhoneNumber)) return jsonResponse({ error: '手机号码格式无效' }, 400);
updates.push("phone_number = ?");
bindings.push(newPhoneNumber);
}
if (updates.length === 0) return jsonResponse({ success: true, message: '未检测到任何更改' });
bindings.push(authenticatedUserEmail);
const updateQuery = `UPDATE users SET ${updates.join(', ')} WHERE email = ?`;
await env.DB.prepare(updateQuery).bind(...bindings).run();
return jsonResponse({ success: true, message: '个人信息更新成功' });
} catch (e) {
if (e instanceof SyntaxError) return jsonResponse({ error: '无效的 JSON 请求体' }, 400);
const errorMsg = e.cause?.message || e.message || "未知数据库错误";
if (errorMsg.includes("UNIQUE constraint failed")) return jsonResponse({ error: '该用户名已被占用 (DB)' }, 409);
return jsonResponse({ error: `更新信息时数据库发生错误: ${errorMsg}` }, 500);
}
}
export async function handleLogout(request, env, sessionIdFromCookie, hostname) {
if (sessionIdFromCookie && env.DB) {
try {
const result = await env.DB.prepare("DELETE FROM sessions WHERE session_id = ?").bind(sessionIdFromCookie).run();
if (!(result && result.success && result.meta.changes > 0)) {
}
} catch (dbError) {
}
}
const cookieDomain = (hostname === 'localhost' || hostname.endsWith('.workers.dev') || hostname.endsWith('pages.dev')) ? '' : `Domain=${hostname}; `;
return new Response(JSON.stringify({ success: true, message: '已登出' }), {
status: 200,
headers: {
'Content-Type': 'application/json;charset=UTF-8',
'Set-Cookie': `AuthToken=; ${cookieDomain}Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; Secure; SameSite=Strict`
}
});
}
export async function handle2FAGenerateSecret(request, env, userEmailFromSession) {
if (!userEmailFromSession) return jsonResponse({ error: '用户未认证' }, 401);
if (!env.DB) return jsonResponse({ error: '服务器配置错误' }, 500);
const userStmt = env.DB.prepare("SELECT username, two_factor_enabled FROM users WHERE email = ?");
const user = await userStmt.bind(userEmailFromSession).first();
if (!user) return jsonResponse({ error: '用户未找到' }, 404);
if (user.two_factor_enabled) return jsonResponse({ error: '两步验证已启用' }, 400);
const secret = await generateTotpSecret();
const issuer = env.OAUTH_ISSUER_NAME || "UserCenterDemo";
const otpauthUri = `otpauth://totp/${issuer}:${encodeURIComponent(user.username || userEmailFromSession)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}`;
return jsonResponse({ success: true, secret: secret, otpauthUri: otpauthUri });
}
export async function handle2FAEnable(request, env, userEmailFromSession) {
if (!userEmailFromSession) return jsonResponse({ error: '用户未认证' }, 401);
try {
const reqBody = await request.json();
const { secret, totpCode } = reqBody;
if (!secret || !totpCode) return jsonResponse({ error: '需要密钥和两步验证码' }, 400);
if (!env.DB) return jsonResponse({ error: '服务器配置错误' }, 500);
const isTotpValid = await verifyTotp(secret, totpCode);
if (!isTotpValid) return jsonResponse({ error: '两步验证码无效' }, 400);
const stmt = env.DB.prepare("UPDATE users SET two_factor_secret = ?, two_factor_enabled = 1 WHERE email = ?");
const result = await stmt.bind(secret, userEmailFromSession).run();
if (result.success && result.meta.changes > 0) return jsonResponse({ success: true, message: '两步验证已成功启用' });
else if (result.success && result.meta.changes === 0) return jsonResponse({ error: '启用两步验证失败，用户不存在或2FA未更新' }, 400);
else return jsonResponse({ error: `启用两步验证时数据库操作失败: ${result.error || '未知D1错误'}` }, 500);
} catch (e) {
if (e instanceof SyntaxError) return jsonResponse({ error: '无效的 JSON 请求体' }, 400);
const errorMessage = e.message || '未知错误';
return jsonResponse({ error: `启用两步验证时出错: ${errorMessage}` }, 500);
}
}
export async function handle2FADisable(request, env, userEmailFromSession) {
if (!userEmailFromSession) return jsonResponse({ error: '用户会话无效，无法禁用两步验证' }, 401);
try {
if (!env.DB) return jsonResponse({ error: '服务器配置错误 (DB_NOT_CONFIGURED)' }, 500);
const userCheckStmt = env.DB.prepare("SELECT two_factor_enabled FROM users WHERE email = ?");
const user = await userCheckStmt.bind(userEmailFromSession).first();
if (!user) return jsonResponse({ error: '用户不存在，无法禁用两步验证' }, 404);
if (!user.two_factor_enabled) return jsonResponse({ success: true, message: '两步验证已经处于禁用状态' });
const stmt = env.DB.prepare("UPDATE users SET two_factor_secret = NULL, two_factor_enabled = 0 WHERE email = ? AND two_factor_enabled = 1");
const result = await stmt.bind(userEmailFromSession).run();
if (result.success && result.meta.changes > 0) return jsonResponse({ success: true, message: '两步验证已成功禁用' });
else if (result.success && result.meta.changes === 0) return jsonResponse({ success: true, message: '两步验证未被禁用，可能之前未启用或用户不匹配' });
else return jsonResponse({ error: `禁用两步验证时数据库操作失败: ${result.error || '未知D1错误'}` }, 500);
} catch (e) {
const errorMessage = e.message || '未知错误';
return jsonResponse({ error: `禁用两步验证时发生意外错误: ${errorMessage}` }, 500);
}
}
export async function handleCreatePasteApiKey(request, env, userEmailFromSession, clientIp) {
if (!userEmailFromSession) return jsonResponse({ error: '用户未认证' }, 401);
try {
const bearerToken = await getPasteApiBearerToken(env);
const reqBody = await request.json();
const { turnstileToken } = reqBody;
const turnstileVerification = await verifyTurnstileToken(turnstileToken, env.TURNSTILE_SECRET_KEY, clientIp);
if (!turnstileVerification.success) {
return jsonResponse({ error: turnstileVerification.error || '人机验证失败', details: turnstileVerification['error-codes'] }, 403);
}
if (!env.DB) return jsonResponse({ error: '服务器配置错误 (DB_NOT_CONFIGURED)' }, 500);
const userStmt = env.DB.prepare("SELECT username FROM users WHERE email = ?");
const user = await userStmt.bind(userEmailFromSession).first();
if (!user || !user.username) {
return jsonResponse({ error: '无法获取用户名以生成API密钥名称' }, 500);
}
const randomHex = Array.from(crypto.getRandomValues(new Uint8Array(3)))
.map(b => b.toString(16).padStart(2, '0')).join('');
const apiKeyName = `${user.username}的云剪贴板密钥${randomHex}`;
const externalApiBody = {
name: apiKeyName, expires_at: null, text_permission: true,
file_permission: true, mount_permission: false, custom_key: null,
};
const response = await fetch(`${EXTERNAL_PASTE_API_BASE_URL}/api/admin/api-keys`, {
method: 'POST',
headers: {
'Authorization': `Bearer ${bearerToken}`, 'Content-Type': 'application/json', 'Accept': 'application/json',
},
body: JSON.stringify(externalApiBody)
});
const responseDataText = await response.text();
let data;
try {
data = JSON.parse(responseDataText);
} catch (e) {
return jsonResponse({ error: `创建外部API密钥失败：无法解析响应 (状态 ${response.status})`, responseText: responseDataText }, 502);
}
if (!response.ok) {
return jsonResponse({ error: data.message || data.error || `创建外部API密钥失败 (状态 ${response.status})` }, response.status);
}
return jsonResponse(data, response.status);
} catch (error) {
if (error.message === "External API authentication token is not configured.") {
return jsonResponse({ error: error.message }, 500);
}
if (error instanceof SyntaxError) return jsonResponse({ error: '无效的 JSON 请求体' }, 400);
const errorMessage = error.message || '未知错误';
return jsonResponse({ error: `代理创建外部API密钥时出错: ${errorMessage}` }, 500);
}
}
export async function handleGetCloudPcKey(request, env, userEmailFromSession) {
if (!userEmailFromSession) return jsonResponse({ error: '用户未认证' }, 401);
if (!env.cloudpc) {
return jsonResponse({ error: "服务器配置错误 (KV_NOT_BOUND)" }, 500);
}
try {
const userKeyRecord = await env.cloudpc.get(userEmailFromSession, { type: "json" });
if (userKeyRecord && userKeyRecord.apiKey) {
const actualApiKey = userKeyRecord.apiKey;
const usageCountStr = await env.cloudpc.get(actualApiKey);
let currentUsage = 0;
if (usageCountStr !== null) {
const parsedCount = parseInt(usageCountStr, 10);
if (!isNaN(parsedCount)) currentUsage = parsedCount;
else currentUsage = 0;
} else {
currentUsage = (typeof userKeyRecord.usageCount === 'number') ? userKeyRecord.usageCount : 0;
}
return jsonResponse({ apiKey: actualApiKey, usageCount: currentUsage, message: "Cloud PC 密钥已存在" }, 200);
} else {
return jsonResponse({ apiKey: null, usageCount: 0, message: "尚未创建 Cloud PC 密钥" }, 200);
}
} catch (e) {
const errorMessage = e.message || '未知错误';
return jsonResponse({ error: `获取 Cloud PC 密钥时出错: ${errorMessage}` }, 500);
}
}
export async function handleCreateCloudPcKey(request, env, userEmailFromSession, clientIp) {
if (!userEmailFromSession) return jsonResponse({ error: '用户未认证' }, 401);
if (!env.cloudpc) {
return jsonResponse({ error: "服务器配置错误 (KV_NOT_BOUND)" }, 500);
}
try {
const existingKvEntry = await env.cloudpc.get(userEmailFromSession);
if (existingKvEntry !== null) {
return jsonResponse({ error: "Cloud PC 密钥已存在，每位用户只能创建一个" }, 409);
}
const reqBody = await request.json();
const { turnstileToken } = reqBody;
const turnstileVerification = await verifyTurnstileToken(turnstileToken, env.TURNSTILE_SECRET_KEY, clientIp);
if (!turnstileVerification.success) {
return jsonResponse({ error: turnstileVerification.error || '人机验证失败', details: turnstileVerification['error-codes'] }, 403);
}
const newApiKey = crypto.randomUUID();
const initialUsageCount = 1;
await env.cloudpc.put(userEmailFromSession, JSON.stringify({ apiKey: newApiKey, usageCount: initialUsageCount }));
await env.cloudpc.put(newApiKey, String(initialUsageCount));
return jsonResponse({
success: true, message: "Cloud PC 密钥创建成功", apiKey: newApiKey, usageCount: initialUsageCount
}, 201);
} catch (e) {
if (e instanceof SyntaxError) return jsonResponse({ error: '无效的 JSON 请求体' }, 400);
const errorMessage = e.message || '未知错误';
return jsonResponse({ error: `创建 Cloud PC 密钥时出错: ${errorMessage}` }, 500);
}
}
export async function handleGetGreenHubKeys(request, env, userEmailFromSession) {
if (!userEmailFromSession) {
return jsonResponse({ error: '用户未认证，无法获取 GreenHub 激活码' }, 401);
}
const preEncodedStripeKey = env.STRIPE_SECRET_KEY;
if (!preEncodedStripeKey) {
return jsonResponse({ error: '服务器配置错误，无法连接到支付服务 (Stripe Key Missing)' }, 500);
}
try {
const stripeApiUrl = 'https://api.stripe.com/v1/customers';
const response = await fetch(stripeApiUrl, {
method: 'GET',
headers: {
'Authorization': `Basic ${preEncodedStripeKey}`,
'Content-Type': 'application/x-www-form-urlencoded'
}
});
if (!response.ok) {
const errorData = await response.json().catch(() => ({ error: { message: '未知 Stripe API 错误' } }));
return jsonResponse({ error: `获取客户数据失败 (Stripe: ${errorData.error?.message || response.statusText})` }, response.status);
}
const result = await response.json();
const licenseCodes = [];
if (result.data && Array.isArray(result.data)) {
for (const customer of result.data) {
if (customer.metadata && customer.metadata.license_code) {
licenseCodes.push(customer.metadata.license_code);
} else if (customer.metadata && Object.keys(customer.metadata).length > 0) {
}
}
}
if (licenseCodes.length > 0) {
return jsonResponse({ success: true, license_codes: licenseCodes });
} else {
return jsonResponse({ success: true, license_codes: [], message: '未找到与您的账户关联的 GreenHub 激活码。' });
}
} catch (error) {
const errorMessage = error.message || '未知错误';
return jsonResponse({ error: `请求 GreenHub 激活码时发生服务器内部错误: ${errorMessage}` }, 500);
}
}
async function getOrCreateConversation(user1Email, user2Email, env) {
const p1 = user1Email < user2Email ? user1Email : user2Email;
const p2 = user1Email < user2Email ? user2Email : user1Email;
let conversation = await env.DB.prepare(
"SELECT conversation_id FROM conversations WHERE participant1_email = ? AND participant2_email = ?"
).bind(p1, p2).first();
if (conversation) {
return conversation.conversation_id;
} else {
const newConversationId = crypto.randomUUID();
const now = Date.now();
try {
await env.DB.prepare(
"INSERT INTO conversations (conversation_id, participant1_email, participant2_email, last_message_at, created_at) VALUES (?, ?, ?, ?, ?)"
).bind(newConversationId, p1, p2, now, now).run();
return newConversationId;
} catch (e) {
return null;
}
}
}
export async function handleSendMessage(request, env, userEmailFromSession) {
if (!userEmailFromSession) return jsonResponse({ error: '用户未认证' }, 401);
if (!env.DB) return jsonResponse({ error: '服务器配置错误' }, 500);
try {
const reqBody = await request.json();
const { receiverEmail, content } = reqBody;
if (!receiverEmail || !content || content.trim() === "") {
return jsonResponse({ error: '接收者邮箱和消息内容不能为空' }, 400);
}
if (receiverEmail === userEmailFromSession) {
return jsonResponse({ error: '不能给自己发送消息' }, 400);
}
if (!isValidEmail(receiverEmail)) {
return jsonResponse({ error: '接收者邮箱格式无效' }, 400);
}
const receiverUser = await env.DB.prepare("SELECT email FROM users WHERE email = ?").bind(receiverEmail).first();
if (!receiverUser) {
return jsonResponse({ error: '接收者用户不存在' }, 404);
}
const conversationId = await getOrCreateConversation(userEmailFromSession, receiverEmail, env);
if (!conversationId) {
return jsonResponse({ error: '无法创建或获取对话' }, 500);
}
const now = Date.now();
await env.DB.prepare("UPDATE conversations SET last_message_at = ? WHERE conversation_id = ?")
.bind(now, conversationId).run();
const messageId = crypto.randomUUID();
await env.DB.prepare(
"INSERT INTO messages (message_id, conversation_id, sender_email, receiver_email, content, sent_at, is_read) VALUES (?, ?, ?, ?, ?, ?, 0)"
).bind(messageId, conversationId, userEmailFromSession, receiverEmail, content.trim(), now).run();
return jsonResponse({ success: true, message: '消息已发送', messageId: messageId, conversationId: conversationId }, 201);
} catch (e) {
if (e instanceof SyntaxError) return jsonResponse({ error: '无效的 JSON 请求体' }, 400);
const errorMessage = e.message || '未知错误';
return jsonResponse({ error: `发送消息时发生服务器内部错误: ${errorMessage}` }, 500);
}
}
export async function handleGetConversations(request, env, userEmailFromSession) {
if (!userEmailFromSession) return jsonResponse({ error: '用户未认证' }, 401);
if (!env.DB) return jsonResponse({ error: '服务器配置错误' }, 500);
try {
const conversations = await env.DB.prepare(
`SELECT
c.conversation_id,
c.last_message_at,
CASE
WHEN c.participant1_email = ? THEN u2.username
ELSE u1.username
END as other_participant_username,
CASE
WHEN c.participant1_email = ? THEN c.participant2_email
ELSE c.participant1_email
END as other_participant_email,
(SELECT content FROM messages m WHERE m.conversation_id = c.conversation_id ORDER BY m.sent_at DESC LIMIT 1) as last_message_content,
(SELECT sender_email FROM messages m WHERE m.conversation_id = c.conversation_id ORDER BY m.sent_at DESC LIMIT 1) as last_message_sender,
(SELECT COUNT(*) FROM messages m WHERE m.conversation_id = c.conversation_id AND m.receiver_email = ? AND m.is_read = 0) as unread_count
FROM conversations c
LEFT JOIN users u1 ON c.participant1_email = u1.email
LEFT JOIN users u2 ON c.participant2_email = u2.email
WHERE c.participant1_email = ? OR c.participant2_email = ?
ORDER BY c.last_message_at DESC`
).bind(userEmailFromSession, userEmailFromSession, userEmailFromSession, userEmailFromSession, userEmailFromSession).all();
return jsonResponse({ success: true, conversations: conversations.results || [] });
} catch (e) {
const errorMessage = e.message || '未知错误';
return jsonResponse({ error: `获取对话列表时发生服务器内部错误: ${errorMessage}` }, 500);
}
}
export async function handleGetMessagesForConversation(request, env, userEmailFromSession, conversationId) {
if (!userEmailFromSession) return jsonResponse({ error: '用户未认证' }, 401);
if (!conversationId) return jsonResponse({ error: '缺少对话ID' }, 400);
if (!env.DB) return jsonResponse({ error: '服务器配置错误' }, 500);
try {
const conversationCheck = await env.DB.prepare(
"SELECT conversation_id FROM conversations WHERE conversation_id = ? AND (participant1_email = ? OR participant2_email = ?)"
).bind(conversationId, userEmailFromSession, userEmailFromSession).first();
if (!conversationCheck) {
return jsonResponse({ error: '无权访问此对话或对话不存在' }, 403);
}
const messages = await env.DB.prepare(
`SELECT m.message_id, m.sender_email, u_sender.username as sender_username, m.content, m.sent_at, m.is_read
FROM messages m
JOIN users u_sender ON m.sender_email = u_sender.email
WHERE m.conversation_id = ?
ORDER BY m.sent_at ASC`
).bind(conversationId).all();
await env.DB.prepare(
"UPDATE messages SET is_read = 1 WHERE conversation_id = ? AND receiver_email = ? AND is_read = 0"
).bind(conversationId, userEmailFromSession).run();
return jsonResponse({ success: true, messages: messages.results || [] });
} catch (e) {
const errorMessage = e.message || '未知错误';
return jsonResponse({ error: `获取消息时发生服务器内部错误: ${errorMessage}` }, 500);
}
}
export async function handleMarkConversationAsRead(request, env, userEmailFromSession, conversationId) {
if (!userEmailFromSession) return jsonResponse({ error: '用户未认证' }, 401);
if (!conversationId) return jsonResponse({ error: '缺少对话ID' }, 400);
if (!env.DB) return jsonResponse({ error: '服务器配置错误' }, 500);
try {
const conversationCheck = await env.DB.prepare(
"SELECT conversation_id FROM conversations WHERE conversation_id = ? AND (participant1_email = ? OR participant2_email = ?)"
).bind(conversationId, userEmailFromSession, userEmailFromSession).first();
if (!conversationCheck) {
return jsonResponse({ error: '无权操作此对话或对话不存在' }, 403);
}
const result = await env.DB.prepare(
"UPDATE messages SET is_read = 1 WHERE conversation_id = ? AND receiver_email = ? AND is_read = 0"
).bind(conversationId, userEmailFromSession).run();
return jsonResponse({ success: true, message: '对话已标记为已读', updated_count: result.meta.changes || 0 });
} catch (e) {
const errorMessage = e.message || '未知错误';
return jsonResponse({ error: `标记已读时发生服务器内部错误: ${errorMessage}` }, 500);
}
}
export async function handleGetUnreadMessageCount(request, env, userEmailFromSession) {
if (!userEmailFromSession) return jsonResponse({ error: '用户未认证' }, 401);
if (!env.DB) return jsonResponse({ error: '服务器配置错误' }, 500);
try {
const result = await env.DB.prepare(
"SELECT COUNT(*) as unread_count FROM messages WHERE receiver_email = ? AND is_read = 0"
).bind(userEmailFromSession).first();
return jsonResponse({ success: true, unread_count: result ? result.unread_count : 0 });
} catch (e) {
const errorMessage = e.message || '未知错误';
return jsonResponse({ error: `获取未读消息数时发生服务器内部错误: ${errorMessage}` }, 500);
}
}
export async function handleAdminListUsers(request, env) {
if (!env.DB) return jsonResponse({ error: '服务器配置错误' }, 500);
try {
const { results } = await env.DB.prepare("SELECT email, username, phone_number, two_factor_enabled, is_active, created_at FROM users ORDER BY created_at DESC").all();
return jsonResponse({ success: true, users: results || [] });
} catch (e) {
const errorMessage = e.message || '未知错误';
return jsonResponse({ error: `获取用户列表时发生服务器内部错误: ${errorMessage}` }, 500);
}
}
export async function handleAdminGetUser(request, env, targetUserEmail) {
if (!env.DB) return jsonResponse({ error: '服务器配置错误' }, 500);
try {
const user = await env.DB.prepare("SELECT email, username, phone_number, two_factor_enabled, is_active, created_at FROM users WHERE email = ?").bind(targetUserEmail).first();
if (!user) return jsonResponse({ error: '用户未找到' }, 404);
return jsonResponse({ success: true, user: user });
} catch (e) {
const errorMessage = e.message || '未知错误';
return jsonResponse({ error: `获取用户信息时发生服务器内部错误: ${errorMessage}` }, 500);
}
}
export async function handleAdminUpdateUser(request, env, targetUserEmail) {
if (!env.DB) return jsonResponse({ error: '服务器配置错误' }, 500);
try {
const reqBody = await request.json();
const { is_active } = reqBody;
if (typeof is_active !== 'boolean') {
return jsonResponse({ error: '请求体中缺少有效的 is_active 字段 (boolean)' }, 400);
}
const result = await env.DB.prepare("UPDATE users SET is_active = ? WHERE email = ?").bind(is_active ? 1 : 0, targetUserEmail).run();
if (result.success && result.meta.changes > 0) {
return jsonResponse({ success: true, message: `用户 ${targetUserEmail} 状态已更新为 ${is_active ? '激活' : '禁用'}` });
} else if (result.success && result.meta.changes === 0) {
return jsonResponse({ error: '用户未找到或状态未改变' }, 404);
} else {
return jsonResponse({ error: '更新用户状态时数据库操作失败' }, 500);
}
} catch (e) {
if (e instanceof SyntaxError) return jsonResponse({ error: '无效的 JSON 请求体' }, 400);
const errorMessage = e.message || '未知错误';
return jsonResponse({ error: `更新用户状态时发生服务器内部错误: ${errorMessage}` }, 500);
}
}
export async function handleAdminListOauthClients(request, env) {
if (!env.DB) return jsonResponse({ error: '服务器配置错误' }, 500);
try {
const { results } = await env.DB.prepare("SELECT client_id, client_name, owner_email, redirect_uris, created_at, status FROM oauth_clients ORDER BY created_at DESC").all();
return jsonResponse({ success: true, clients: results || [] });
} catch (e) {
const errorMessage = e.message || '未知错误';
return jsonResponse({ error: `获取OAuth应用列表时发生服务器内部错误: ${errorMessage}` }, 500);
}
}
export async function handleAdminGetOauthClient(request, env, targetClientId) {
if (!env.DB) return jsonResponse({ error: '服务器配置错误' }, 500);
try {
const client = await env.DB.prepare("SELECT client_id, client_name, owner_email, client_website, client_description, redirect_uris, allowed_scopes, grant_types_allowed, created_at, status FROM oauth_clients WHERE client_id = ?").bind(targetClientId).first();
if (!client) return jsonResponse({ error: 'OAuth应用未找到' }, 404);
return jsonResponse({ success: true, client: client });
} catch (e) {
const errorMessage = e.message || '未知错误';
return jsonResponse({ error: `获取OAuth应用信息时发生服务器内部错误: ${errorMessage}` }, 500);
}
}
export async function handleAdminUpdateOauthClient(request, env, targetClientId) {
if (!env.DB) return jsonResponse({ error: '服务器配置错误' }, 500);
try {
const reqBody = await request.json();
const { status } = reqBody;
if (typeof status !== 'string' || !['active', 'suspended'].includes(status.toLowerCase())) {
return jsonResponse({ error: '请求体中缺少有效的 status 字段 (active/suspended)' }, 400);
}
const result = await env.DB.prepare("UPDATE oauth_clients SET status = ? WHERE client_id = ?").bind(status.toLowerCase(), targetClientId).run();
if (result.success && result.meta.changes > 0) {
return jsonResponse({ success: true, message: `OAuth应用 ${targetClientId} 状态已更新为 ${status}` });
} else if (result.success && result.meta.changes === 0) {
return jsonResponse({ error: 'OAuth应用未找到或状态未改变' }, 404);
} else {
return jsonResponse({ error: '更新OAuth应用状态时数据库操作失败' }, 500);
}
} catch (e) {
if (e instanceof SyntaxError) return jsonResponse({ error: '无效的 JSON 请求体' }, 400);
const errorMessage = e.message || '未知错误';
return jsonResponse({ error: `更新OAuth应用状态时发生服务器内部错误: ${errorMessage}` }, 500);
}
}
