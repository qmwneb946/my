// OAuth 2.0 / OIDC 服务核心逻辑和客户端管理 API
// Handles /oauth/* core protocol endpoints and /api/oauth/clients/* for client management

import { jsonResponse, OAUTH_ISSUER_URL, hashPassword, constantTimeCompare, generateClientSecret, isValidEmail } from './helpers.js';
import { verifyTurnstileToken } from './turnstile-handler.js';
import { signJwt, verifyJwt, generateIdTokenPayload, generateAccessTokenPayload } from './jwt-utils.js';
import { generateConsentScreenHtml, generateErrorPageHtml } from './html-ui.js'; // 确保导入了 HTML 生成函数

// --- OIDC Discovery Endpoint Handlers ---

export async function handleOpenIDConfiguration(request, env) {
    const issuer = OAUTH_ISSUER_URL(env, request);
    const configuration = {
        issuer: issuer,
        authorization_endpoint: `${issuer}/oauth/authorize`,
        token_endpoint: `${issuer}/oauth/token`,
        userinfo_endpoint: `${issuer}/oauth/userinfo`,
        jwks_uri: `${issuer}/.well-known/jwks.json`,
        scopes_supported: ["openid", "profile", "email", "phone"],
        response_types_supported: ["code"],
        grant_types_supported: ["authorization_code", "refresh_token"],
        subject_types_supported: ["public"],
        id_token_signing_alg_values_supported: [env.OAUTH_SIGNING_ALG || "RS256"],
        token_endpoint_auth_methods_supported: ["client_secret_post", "client_secret_basic"],
        claims_supported: [
            "sub", "iss", "aud", "exp", "iat", "auth_time", "nonce",
            "email", "email_verified", "name", "username", "phone_number", "phone_number_verified"
        ],
    };
    return jsonResponse(configuration);
}

export async function handleJwks(request, env) {
    try {
        const publicKeyJwkString = env.OAUTH_SIGNING_KEY_PUBLIC;
        if (!publicKeyJwkString) {
            console.error("OAUTH_SIGNING_KEY_PUBLIC is not configured in worker environment.");
            return jsonResponse({ error: "JWKS 的服务器配置错误。" }, 500);
        }
        const publicKeyJwk = JSON.parse(publicKeyJwkString);
        const jwks = {
            keys: [publicKeyJwk]
        };
        return jsonResponse(jwks);
    } catch (e) {
        console.error("生成 JWKS 响应时出错:", e);
        return jsonResponse({ error: "生成 JWKS 响应时出错。" }, 500);
    }
}

// --- OAuth 2.0 / OIDC Core Protocol Endpoint Handlers ---

export async function handleOAuthAuthorize(request, env) {
    const url = new URL(request.url);
    const rayId = request.headers.get('cf-ray') || crypto.randomUUID();
    
    if (request.method === 'GET') {
        const params = url.searchParams;
        console.log(`[${rayId}][OAuth Authorize GET] Received params:`, Object.fromEntries(params));

        const responseType = params.get('response_type');
        const clientId = params.get('client_id');
        const redirectUri = params.get('redirect_uri');
        const scope = params.get('scope');
        const state = params.get('state');
        const nonce = params.get('nonce'); // OIDC specific

        if (responseType !== 'code') {
            return new Response(generateErrorPageHtml("无效的请求", "仅支持 'code' 响应类型。"), { status: 400, headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
        }
        if (!clientId || !redirectUri || !scope) {
            return new Response(generateErrorPageHtml("无效的请求", "缺少 client_id, redirect_uri 或 scope 参数。"), { status: 400, headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
        }

        const clientStmt = env.DB.prepare("SELECT client_id, client_name, redirect_uris, allowed_scopes FROM oauth_clients WHERE client_id = ?");
        const client = await clientStmt.bind(clientId).first();

        if (!client) {
            console.warn(`[${rayId}][OAuth Authorize GET] Invalid client_id: ${clientId}`);
            return new Response(generateErrorPageHtml("无效的客户端", "客户端 ID 无效。"), { status: 400, headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
        }

        let registeredRedirectUris;
        try {
            registeredRedirectUris = JSON.parse(client.redirect_uris);
            if (!Array.isArray(registeredRedirectUris) || !registeredRedirectUris.includes(redirectUri)) {
                console.warn(`[${rayId}][OAuth Authorize GET] Invalid redirect_uri: ${redirectUri} for client: ${clientId}. Registered: ${client.redirect_uris}`);
                return new Response(generateErrorPageHtml("无效的请求", "提供的 redirect_uri 未在客户端注册。"), { status: 400, headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
            }
        } catch (e) {
            console.error(`[${rayId}][OAuth Authorize GET] 解析 redirect_uris 失败:`, client.redirect_uris, e);
            return new Response(generateErrorPageHtml("服务器错误", "无法验证 redirect_uri。"), { status: 500, headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
        }

        const cookieHeader = request.headers.get('Cookie');
        let sessionIdFromCookie = null;
        if (cookieHeader) {
            const authCookieString = cookieHeader.split(';').find(row => row.trim().startsWith('AuthToken='));
            if (authCookieString) sessionIdFromCookie = authCookieString.split('=')[1]?.trim();
        }
        
        let userEmail;
        if (sessionIdFromCookie && env.DB) {
            const session = await env.DB.prepare("SELECT user_email, expires_at FROM sessions WHERE session_id = ?").bind(sessionIdFromCookie).first();
            if (session && session.expires_at > Math.floor(Date.now()/1000)) {
                userEmail = session.user_email;
            }
        }

        if (!userEmail) {
            const loginUrl = new URL(`${OAUTH_ISSUER_URL(env, request)}/user/login`);
            const originalOAuthParams = new URLSearchParams(params).toString();
            loginUrl.searchParams.set('return_to', `${url.pathname}?${originalOAuthParams}`);
            loginUrl.searchParams.set('oauth_flow', 'true');
            console.log(`[${rayId}][OAuth Authorize GET] User not logged in. Redirecting to login: ${loginUrl.toString()}`);
            return Response.redirect(loginUrl.toString(), 302);
        }

        console.log(`[${rayId}][OAuth Authorize GET] User ${userEmail} authenticated. Displaying consent screen.`);
        const userStmt = env.DB.prepare("SELECT username FROM users WHERE email = ?");
        const user = await userStmt.bind(userEmail).first();
        if (!user) { // 应该不会发生，因为会话有效
             console.error(`[${rayId}][OAuth Authorize GET] Authenticated user ${userEmail} not found in users table.`);
             return new Response(generateErrorPageHtml("服务器错误", "无法检索用户信息。"), { status: 500, headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
        }


        // 渲染同意屏幕
        const consentHtml = generateConsentScreenHtml({
            clientName: client.client_name,
            requestedScopes: scope.split(" "),
            user: user, // 传递用户信息以显示
            formAction: `${OAUTH_ISSUER_URL(env, request)}/oauth/authorize`, // 表单提交回此端点
            clientId, redirectUri, scope, state, nonce, responseType
        }); // 传递 env 以便 generateConsentScreenHtml 可以访问 CDN_BASE_URL
        return new Response(consentHtml, { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });

    } else if (request.method === 'POST') {
        // 处理同意屏幕的表单提交
        const formData = await request.formData();
        console.log(`[${rayId}][OAuth Authorize POST] Received consent decision:`, Object.fromEntries(formData));

        const decision = formData.get('decision');
        const clientId = formData.get('client_id');
        const redirectUri = formData.get('redirect_uri');
        const scope = formData.get('scope');
        const state = formData.get('state');
        const nonce = formData.get('nonce');
        // const responseType = formData.get('response_type'); // 应该还是 'code'

        const cookieHeader = request.headers.get('Cookie');
        let sessionIdFromCookie = null;
        if (cookieHeader) {
            const authCookieString = cookieHeader.split(';').find(row => row.trim().startsWith('AuthToken='));
            if (authCookieString) sessionIdFromCookie = authCookieString.split('=')[1]?.trim();
        }
        let userEmail;
        if (sessionIdFromCookie && env.DB) {
            const session = await env.DB.prepare("SELECT user_email FROM sessions WHERE session_id = ? AND expires_at > ?")
                                .bind(sessionIdFromCookie, Math.floor(Date.now()/1000))
                                .first();
            if (session) userEmail = session.user_email;
        }

        if (!userEmail) {
            console.warn(`[${rayId}][OAuth Authorize POST] User session expired or invalid during consent submission.`);
            return new Response(generateErrorPageHtml("会话无效", "您的会话已过期，请重新开始授权流程。"), { status: 400, headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
        }

        const redirect = new URL(redirectUri);
        if (state) redirect.searchParams.set('state', state);

        if (decision === 'allow') {
            const authorizationCode = crypto.randomUUID();
            const codeLifetime = parseInt(env.AUTHORIZATION_CODE_LIFETIME_SECONDS || "600");
            const expiresAt = Math.floor(Date.now() / 1000) + codeLifetime;

            try {
                const codeStmt = env.DB.prepare(
                    "INSERT INTO authorization_codes (code, user_email, client_id, redirect_uri, scopes, expires_at, nonce, used) VALUES (?, ?, ?, ?, ?, ?, ?, 0)"
                );
                await codeStmt.bind(authorizationCode, userEmail, clientId, redirectUri, scope, expiresAt, nonce).run();
                console.log(`[${rayId}][OAuth Authorize POST] Consent granted. Authorization code ${authorizationCode} generated for user ${userEmail}, client ${clientId}.`);
                
                redirect.searchParams.set('code', authorizationCode);
                return Response.redirect(redirect.toString(), 302);
            } catch (dbError) {
                console.error(`[${rayId}][OAuth Authorize POST] 存储授权码失败:`, dbError);
                redirect.searchParams.set('error', 'server_error');
                redirect.searchParams.set('error_description', '无法生成授权码。');
                return Response.redirect(redirect.toString(), 302);
            }
        } else { // decision === 'deny' or other
            console.log(`[${rayId}][OAuth Authorize POST] Consent denied by user ${userEmail} for client ${clientId}.`);
            redirect.searchParams.set('error', 'access_denied');
            redirect.searchParams.set('error_description', '用户拒绝了授权请求。');
            return Response.redirect(redirect.toString(), 302);
        }
    } else {
        return new Response("不支持的请求方法。", { status: 405 });
    }
}


export async function handleOAuthToken(request, env) {
    const rayId = request.headers.get('cf-ray') || crypto.randomUUID();
    console.log(`[${rayId}][OAuth Token] Request received.`);
    const formData = await request.formData();
    console.log(`[${rayId}][OAuth Token] FormData:`, Object.fromEntries(formData));

    const grantType = formData.get('grant_type');
    const code = formData.get('code');
    const redirectUri = formData.get('redirect_uri');
    const refreshToken = formData.get('refresh_token');

    let clientId = formData.get('client_id');
    let clientSecret = formData.get('client_secret');

    const authHeader = request.headers.get('Authorization');
    if (authHeader && authHeader.toLowerCase().startsWith('basic ')) {
        try {
            const credentials = atob(authHeader.substring(6)).split(':', 2);
            clientId = credentials[0];
            clientSecret = credentials[1];
            console.log(`[${rayId}][OAuth Token] Client credentials from Basic Auth header.`);
        } catch (e) {
            console.warn(`[${rayId}][OAuth Token] Error parsing Basic Auth header:`, e);
            return jsonResponse({ error: 'invalid_client', error_description: '无效的客户端认证凭据 (Basic Auth)。' }, 400);
        }
    }

    if (!clientId) {
        return jsonResponse({ error: 'invalid_client', error_description: '缺少客户端 ID。' }, 400);
    }

    const clientStmt = env.DB.prepare("SELECT client_id, client_secret_hash, redirect_uris, allowed_scopes, grant_types_allowed FROM oauth_clients WHERE client_id = ?");
    const client = await clientStmt.bind(clientId).first();

    if (!client) {
        console.warn(`[${rayId}][OAuth Token] Invalid client_id: ${clientId}`);
        return jsonResponse({ error: 'invalid_client', error_description: '客户端 ID 无效。' }, 401);
    }

    if (clientSecret) {
        const secretMatch = await constantTimeCompare(client.client_secret_hash, await hashPassword(clientSecret));
        if (!secretMatch) {
            console.warn(`[${rayId}][OAuth Token] Invalid client_secret for client_id: ${clientId}`);
            return jsonResponse({ error: 'invalid_client', error_description: '客户端密钥无效。' }, 401);
        }
    } else {
        // 假设所有通过此流程注册的客户端都是机密的，需要密钥。
        // 如果支持公共客户端，则需要更复杂的逻辑来判断客户端类型。
        console.log(`[${rayId}][OAuth Token] Client ${clientId} attempting token exchange, client_secret not provided.`);
        return jsonResponse({ error: 'invalid_client', error_description: '需要客户端密钥。' }, 401);
    }


    if (grantType === 'authorization_code') {
        if (!code || !redirectUri) {
            return jsonResponse({ error: 'invalid_request', error_description: '缺少 code 或 redirect_uri。' }, 400);
        }

        const codeStmt = env.DB.prepare("SELECT user_email, scopes, expires_at, used, nonce FROM authorization_codes WHERE code = ? AND client_id = ? AND redirect_uri = ?");
        const authCode = await codeStmt.bind(code, clientId, redirectUri).first();

        if (!authCode) {
            console.warn(`[${rayId}][OAuth Token] Invalid or mismatched authorization code: ${code} for client ${clientId}`);
            return jsonResponse({ error: 'invalid_grant', error_description: '授权码无效或不匹配。' }, 400);
        }
        if (authCode.used) {
            console.warn(`[${rayId}][OAuth Token] Authorization code already used: ${code}`);
            return jsonResponse({ error: 'invalid_grant', error_description: '授权码已被使用。' }, 400);
        }
        if (authCode.expires_at < Math.floor(Date.now() / 1000)) {
            console.warn(`[${rayId}][OAuth Token] Authorization code expired: ${code}`);
            return jsonResponse({ error: 'invalid_grant', error_description: '授权码已过期。' }, 400);
        }

        const markUsedStmt = env.DB.prepare("UPDATE authorization_codes SET used = 1 WHERE code = ?");
        await markUsedStmt.bind(code).run();
        console.log(`[${rayId}][OAuth Token] Authorization code ${code} marked as used.`);

        const userStmt = env.DB.prepare("SELECT email, username, phone_number FROM users WHERE email = ?");
        const user = await userStmt.bind(authCode.user_email).first();
        if (!user) {
            console.error(`[${rayId}][OAuth Token] User not found for email: ${authCode.user_email}`);
            return jsonResponse({ error: 'server_error', error_description: '无法找到用户信息。' }, 500);
        }

        const scopes = authCode.scopes.split(" ");

        const idTokenPayload = generateIdTokenPayload(user, clientId, authCode.nonce, scopes, request, env);
        const accessTokenPayload = generateAccessTokenPayload(user.email, clientId, scopes, request, env);

        const idToken = await signJwt(idTokenPayload, env);
        const accessToken = await signJwt(accessTokenPayload, env);

        const responsePayload = {
            access_token: accessToken,
            token_type: "Bearer",
            expires_in: parseInt(env.ACCESS_TOKEN_LIFETIME_SECONDS || "3600"),
            id_token: idToken,
            scope: scopes.join(" ")
        };
        console.log(`[${rayId}][OAuth Token] Tokens generated for user ${user.email}, client ${clientId}.`);
        return jsonResponse(responsePayload);

    } else if (grantType === 'refresh_token') {
        console.warn(`[${rayId}][OAuth Token] Refresh token grant type not yet fully implemented.`);
        return jsonResponse({ error: 'unsupported_grant_type', error_description: '刷新令牌功能暂未实现。' }, 501);
    } else {
        return jsonResponse({ error: 'unsupported_grant_type', error_description: `不支持的 grant_type: ${grantType}。` }, 400);
    }
}


export async function handleOAuthUserInfo(request, env) {
    const rayId = request.headers.get('cf-ray') || crypto.randomUUID();
    const authHeader = request.headers.get('Authorization');
    if (!authHeader || !authHeader.toLowerCase().startsWith('bearer ')) {
        return jsonResponse({ error: 'invalid_request', error_description: '缺少或格式错误的 Authorization 头部。' }, 400);
    }
    const accessToken = authHeader.substring(7);
    console.log(`[${rayId}][OAuth UserInfo] Received access token.`);

    try {
        const decodedAccessToken = await verifyJwt(accessToken, env);
        if (!decodedAccessToken) {
            console.warn(`[${rayId}][OAuth UserInfo] Invalid or expired access token.`);
            return jsonResponse({ error: 'invalid_token', error_description: '访问令牌无效或已过期。' }, 401);
        }

        if (!decodedAccessToken.sub) {
            console.warn(`[${rayId}][OAuth UserInfo] Access token missing subject (sub).`);
            return jsonResponse({ error: 'invalid_token', error_description: '访问令牌缺少 subject。' }, 401);
        }

        const userStmt = env.DB.prepare("SELECT email, username, phone_number FROM users WHERE email = ?");
        const user = await userStmt.bind(decodedAccessToken.sub).first();

        if (!user) {
            console.warn(`[${rayId}][OAuth UserInfo] User not found for subject: ${decodedAccessToken.sub}`);
            return jsonResponse({ error: 'invalid_token', error_description: '找不到与令牌关联的用户。' }, 401);
        }

        const scopes = decodedAccessToken.scope ? decodedAccessToken.scope.split(" ") : [];
        const userInfoPayload = { sub: user.email };

        if (scopes.includes("profile")) {
            userInfoPayload.name = user.username;
            userInfoPayload.username = user.username;
        }
        if (scopes.includes("email")) {
            userInfoPayload.email = user.email;
            userInfoPayload.email_verified = true;
        }
        if (scopes.includes("phone") && user.phone_number) {
            userInfoPayload.phone_number = user.phone_number;
        }
        console.log(`[${rayId}][OAuth UserInfo] Returning user info for ${user.email}`);
        return jsonResponse(userInfoPayload);

    } catch (e) {
        console.error(`[${rayId}][OAuth UserInfo] Error processing UserInfo request:`, e);
        return jsonResponse({ error: 'server_error', error_description: '处理 UserInfo 请求时发生内部错误。' }, 500);
    }
}


// --- OAuth Client Management API Handlers (/api/oauth/clients) ---
export async function handleRegisterOauthClient(request, env, userEmailFromSession) {
    if (!userEmailFromSession) return jsonResponse({ error: '用户未认证，无法注册应用' }, 401);
    if (!env.DB) return jsonResponse({ error: '服务器配置错误 (DB_NOT_CONFIGURED)' }, 500);
    const rayId = request.headers.get('cf-ray') || crypto.randomUUID();

    try {
        const reqBody = await request.json();
        const { clientName, clientWebsite, clientDescription, redirectUri, turnstileToken } = reqBody;
        const clientIp = request.headers.get('CF-Connecting-IP');

        const turnstileVerification = await verifyTurnstileToken(turnstileToken, env.TURNSTILE_SECRET_KEY, clientIp);
        if (!turnstileVerification.success) {
            return jsonResponse({ error: turnstileVerification.error || '人机验证失败', details: turnstileVerification['error-codes'] }, 403);
        }

        if (!clientName || clientName.trim().length === 0 || clientName.length > 50) {
            return jsonResponse({ error: '应用名称不能为空且长度不能超过50个字符' }, 400);
        }
        if (!redirectUri || redirectUri.trim().length === 0) {
            return jsonResponse({ error: '回调地址 (Redirect URI) 不能为空' }, 400);
        }
        let parsedRedirectUri;
        try {
            parsedRedirectUri = new URL(redirectUri.trim());
            if (parsedRedirectUri.protocol !== "https:") {
                 return jsonResponse({ error: '回调地址必须使用 HTTPS 协议' }, 400);
            }
        } catch (e) {
            return jsonResponse({ error: '回调地址不是一个有效的 URL' }, 400);
        }
        if (clientWebsite && clientWebsite.trim().length > 200) return jsonResponse({ error: '应用主页长度不能超过200字符'}, 400);
        if (clientDescription && clientDescription.trim().length > 200) return jsonResponse({ error: '应用描述长度不能超过200字符'}, 400);

        const clientId = crypto.randomUUID();
        const rawClientSecret = generateClientSecret(40);
        const clientSecretHash = await hashPassword(rawClientSecret);
        const createdAt = Math.floor(Date.now() / 1000);
        const allowedScopes = JSON.stringify(["openid", "profile", "email", "phone"]);
        const grantTypesAllowed = JSON.stringify(["authorization_code", "refresh_token"]);

        const stmt = env.DB.prepare(
            `INSERT INTO oauth_clients (client_id, client_secret_hash, owner_email, client_name, client_website, client_description, redirect_uris, allowed_scopes, grant_types_allowed, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        );
        await stmt.bind(
            clientId, clientSecretHash, userEmailFromSession,
            clientName.trim(),
            clientWebsite ? clientWebsite.trim() : null,
            clientDescription ? clientDescription.trim() : null,
            JSON.stringify([parsedRedirectUri.toString()]),
            allowedScopes, grantTypesAllowed, createdAt
        ).run();
        console.log(`[${rayId}][Register OAuth Client] Client ${clientId} registered for user ${userEmailFromSession}.`);
        return jsonResponse({
            success: true, message: '应用注册成功！请妥善保管客户端密钥，它仅显示一次。',
            client_id: clientId, client_secret: rawClientSecret
        }, 201);

    } catch (e) {
        console.error(`[${rayId}][Register OAuth Client] Error:`, e);
        if (e instanceof SyntaxError) return jsonResponse({ error: '无效的 JSON 请求体' }, 400);
        if (e.message && e.message.includes("UNIQUE constraint failed")) {
            return jsonResponse({ error: '无法注册应用，可能存在唯一性冲突，请重试。' }, 409);
        }
        return jsonResponse({ error: '注册应用时发生服务器内部错误' }, 500);
    }
}

export async function handleListOauthClients(request, env, userEmailFromSession) {
    if (!userEmailFromSession) return jsonResponse({ error: '用户未认证，无法获取应用列表' }, 401);
    if (!env.DB) return jsonResponse({ error: '服务器配置错误 (DB_NOT_CONFIGURED)' }, 500);
    const rayId = request.headers.get('cf-ray') || crypto.randomUUID();

    try {
        const stmt = env.DB.prepare(
            "SELECT client_id, client_name, client_website, client_description, redirect_uris, created_at FROM oauth_clients WHERE owner_email = ? ORDER BY created_at DESC"
        );
        const { results } = await stmt.bind(userEmailFromSession).all();
        console.log(`[${rayId}][List OAuth Clients] Found ${results ? results.length : 0} clients for user ${userEmailFromSession}.`);
        return jsonResponse({
            success: true,
            clients: results || []
        });
    } catch (e) {
        console.error(`[${rayId}][List OAuth Clients] Error:`, e);
        return jsonResponse({ error: '获取应用列表时发生服务器内部错误' }, 500);
    }
}

export async function handleDeleteOauthClient(request, env, userEmailFromSession, clientIdFromPath) {
    if (!userEmailFromSession) return jsonResponse({ error: '用户未认证，无法删除应用' }, 401);
    if (!clientIdFromPath) return jsonResponse({ error: '缺少客户端 ID' }, 400);
    if (!env.DB) return jsonResponse({ error: '服务器配置错误 (DB_NOT_CONFIGURED)' }, 500);
    const rayId = request.headers.get('cf-ray') || crypto.randomUUID();

    try {
        const clientCheckStmt = env.DB.prepare("SELECT owner_email FROM oauth_clients WHERE client_id = ?");
        const client = await clientCheckStmt.bind(clientIdFromPath).first();

        if (!client) {
            console.warn(`[${rayId}][Delete OAuth Client] Client ${clientIdFromPath} not found.`);
            return jsonResponse({ error: '应用未找到' }, 404);
        }
        if (client.owner_email !== userEmailFromSession) {
            console.warn(`[${rayId}][Delete OAuth Client] User ${userEmailFromSession} not authorized to delete client ${clientIdFromPath}. Owner: ${client.owner_email}`);
            return jsonResponse({ error: '无权删除此应用' }, 403);
        }

        console.log(`[${rayId}][Delete OAuth Client] Attempting to delete dependent records for client ${clientIdFromPath}`);
        const deleteAuthCodesStmt = env.DB.prepare("DELETE FROM authorization_codes WHERE client_id = ?");
        const authCodesDeletion = await deleteAuthCodesStmt.bind(clientIdFromPath).run();
        console.log(`[${rayId}][Delete OAuth Client] Deleted ${authCodesDeletion.meta.changes} authorization_codes for client ${clientIdFromPath}.`);

        const deleteRefreshTokensStmt = env.DB.prepare("DELETE FROM refresh_tokens WHERE client_id = ?");
        const refreshTokensDeletion = await deleteRefreshTokensStmt.bind(clientIdFromPath).run();
        console.log(`[${rayId}][Delete OAuth Client] Deleted ${refreshTokensDeletion.meta.changes} refresh_tokens for client ${clientIdFromPath}.`);

        const deleteClientStmt = env.DB.prepare("DELETE FROM oauth_clients WHERE client_id = ? AND owner_email = ?");
        const clientDeletion = await deleteClientStmt.bind(clientIdFromPath, userEmailFromSession).run();

        if (clientDeletion.success && clientDeletion.meta.changes > 0) {
            console.log(`[${rayId}][Delete OAuth Client] Client ${clientIdFromPath} successfully deleted by user ${userEmailFromSession}.`);
            return jsonResponse({ success: true, message: '应用已成功删除' }, 200);
        } else if (clientDeletion.success && clientDeletion.meta.changes === 0) {
            console.warn(`[${rayId}][Delete OAuth Client] Client ${clientIdFromPath} not found for deletion or owner mismatch during final delete operation, though initial check passed.`);
            return jsonResponse({ error: '应用在删除过程中未找到或权限不匹配' }, 404);
        } else {
            console.error(`[${rayId}][Delete OAuth Client] Database operation failed for client ${clientIdFromPath}. D1 success: ${clientDeletion.success}, meta: ${JSON.stringify(clientDeletion.meta)}`);
            return jsonResponse({ error: '删除应用时数据库操作失败' }, 500);
        }
    } catch (e) {
        console.error(`[${rayId}][Delete OAuth Client] Error deleting client ${clientIdFromPath}:`, e);
        return jsonResponse({ error: '删除应用时发生服务器内部错误' }, 500);
    }
}

export async function handleUpdateOauthClient(request, env, userEmailFromSession, clientIdFromPath) {
    if (!userEmailFromSession) return jsonResponse({ error: '用户未认证，无法更新应用' }, 401);
    if (!clientIdFromPath) return jsonResponse({ error: '缺少客户端 ID' }, 400);
    if (!env.DB) return jsonResponse({ error: '服务器配置错误 (DB_NOT_CONFIGURED)' }, 500);
    const rayId = request.headers.get('cf-ray') || crypto.randomUUID();

    try {
        const reqBody = await request.json();
        const { clientName, clientWebsite, clientDescription, redirectUri } = reqBody;

        const clientCheckStmt = env.DB.prepare("SELECT owner_email FROM oauth_clients WHERE client_id = ?");
        const client = await clientCheckStmt.bind(clientIdFromPath).first();

        if (!client) {
            return jsonResponse({ error: '应用未找到' }, 404);
        }
        if (client.owner_email !== userEmailFromSession) {
            return jsonResponse({ error: '无权更新此应用' }, 403);
        }

        const updates = [];
        const bindings = [];

        if (clientName !== undefined) {
            const trimmedClientName = clientName.trim();
            if (trimmedClientName.length === 0 || trimmedClientName.length > 50) {
                return jsonResponse({ error: '应用名称不能为空且长度不能超过50个字符' }, 400);
            }
            updates.push("client_name = ?");
            bindings.push(trimmedClientName);
        }
        if (clientWebsite !== undefined) {
            const trimmedWebsite = clientWebsite ? clientWebsite.trim() : null;
            if (trimmedWebsite && trimmedWebsite.length > 200) return jsonResponse({ error: '应用主页长度不能超过200字符'}, 400);
            if (trimmedWebsite) { try { new URL(trimmedWebsite); } catch (e) { return jsonResponse({ error: '应用主页不是一个有效的 URL'}, 400);}}
            updates.push("client_website = ?");
            bindings.push(trimmedWebsite);
        }
        if (clientDescription !== undefined) {
            const trimmedDescription = clientDescription ? clientDescription.trim() : null;
            if (trimmedDescription && trimmedDescription.length > 200) return jsonResponse({ error: '应用描述长度不能超过200字符'}, 400);
            updates.push("client_description = ?");
            bindings.push(trimmedDescription);
        }
        if (redirectUri !== undefined) {
            const trimmedRedirectUri = redirectUri.trim();
            if (trimmedRedirectUri.length === 0) return jsonResponse({ error: '回调地址 (Redirect URI) 不能为空' }, 400);
            let parsedRedirectUri;
            try {
                parsedRedirectUri = new URL(trimmedRedirectUri);
                if (parsedRedirectUri.protocol !== "https:") {
                     return jsonResponse({ error: '回调地址必须使用 HTTPS 协议' }, 400);
                }
            } catch (e) {
                return jsonResponse({ error: '回调地址不是一个有效的 URL' }, 400);
            }
            updates.push("redirect_uris = ?");
            bindings.push(JSON.stringify([parsedRedirectUri.toString()]));
        }

        if (updates.length === 0) {
            return jsonResponse({ success: true, message: '未提供任何更新信息，无需更改。' }, 200);
        }

        bindings.push(clientIdFromPath);
        bindings.push(userEmailFromSession);

        const updateQuery = `UPDATE oauth_clients SET ${updates.join(', ')} WHERE client_id = ? AND owner_email = ?`;
        const { success, meta } = await env.DB.prepare(updateQuery).bind(...bindings).run();

        if (success && meta.changes > 0) {
            console.log(`[${rayId}][Update OAuth Client] Client ${clientIdFromPath} updated by user ${userEmailFromSession}.`);
            return jsonResponse({ success: true, message: '应用信息已成功更新' });
        } else if (success && meta.changes === 0) {
            console.warn(`[${rayId}][Update OAuth Client] No changes made for client ${clientIdFromPath}. Possible reasons: data same as current, or record not found/owner mismatch during update.`);
            return jsonResponse({ success: true, message: '未进行任何更改（可能提交的数据与当前数据相同）。' });
        } else {
            console.error(`[${rayId}][Update OAuth Client] Database operation failed for client ${clientIdFromPath}. D1 success: ${success}, meta: ${JSON.stringify(meta)}`);
            return jsonResponse({ error: '更新应用时数据库操作失败' }, 500);
        }

    } catch (e) {
        console.error(`[${rayId}][Update OAuth Client] Error updating client ${clientIdFromPath}:`, e);
        if (e instanceof SyntaxError) return jsonResponse({ error: '无效的 JSON 请求体' }, 400);
        return jsonResponse({ error: '更新应用时发生服务器内部错误' }, 500);
    }
}
