// Cloudflare Worker 主入口文件 (worker.js)
// 负责请求路由分发、基本配置提供和错误处理

import {
    authenticateApiRequest,
    handleGetMe,
    handleRegister,
    handleLogin,
    handleLogin2FAVerify,
    handleChangePassword,
    handleUpdateProfile,
    handleLogout,
    handle2FAGenerateSecret,
    handle2FAEnable,
    handle2FADisable,
    handleCreatePasteApiKey,
    handleGetCloudPcKey,
    handleCreateCloudPcKey,
    handleSendMessage, // 新增：导入私信处理函数
    handleGetConversations,
    handleGetMessagesForConversation,
    handleMarkConversationAsRead,
    handleGetUnreadMessageCount
} from './api-handlers.js';

import {
    handleOpenIDConfiguration,
    handleJwks,
    handleOAuthAuthorize,
    handleOAuthToken,
    handleOAuthUserInfo,
    handleRegisterOauthClient,
    handleListOauthClients,
    handleUpdateOauthClient,
    handleDeleteOauthClient
} from './oauth-server.js';

import { generateHtmlUi, generateErrorPageHtml } from './html-ui.js';
import { jsonResponse, OAUTH_ISSUER_URL } from './helpers.js';

export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        const path = url.pathname;
        const method = request.method;
        const rayId = request.headers.get('cf-ray') || crypto.randomUUID();

        console.log(`[${rayId}] Request received: ${method} ${path}`);

        try {
            // --- OIDC Discovery Endpoints ---
            if (method === 'GET' && path === '/.well-known/openid-configuration') {
                console.log(`[${rayId}][ROUTE_MATCH] /.well-known/openid-configuration`);
                return handleOpenIDConfiguration(request, env);
            }
            if (method === 'GET' && path === '/.well-known/jwks.json') {
                console.log(`[${rayId}][ROUTE_MATCH] /.well-known/jwks.json`);
                return handleJwks(request, env);
            }

            // --- OAuth 2.0 / OIDC Core Endpoints ---
            if (path.startsWith('/oauth/')) {
                console.log(`[${rayId}][ROUTE_MATCH] /oauth/* path: ${path}`);
                if (path === '/oauth/authorize') {
                    return handleOAuthAuthorize(request, env);
                }
                if (path === '/oauth/token' && method === 'POST') {
                    return handleOAuthToken(request, env);
                }
                if (path === '/oauth/userinfo' && (method === 'GET' || method === 'POST')) {
                    return handleOAuthUserInfo(request, env);
                }
                console.warn(`[${rayId}][ROUTE_MISS_OAUTH] Unhandled /oauth/ path: ${path}`);
                return jsonResponse({ error: 'OAuth/OIDC 端点未找到或方法不允许' }, 404);
            }

            // --- API Endpoints ---
            if (path.startsWith('/api/')) {
                console.log(`[${rayId}][ROUTE_MATCH] /api/* path: ${path}`);
                if (path === '/api/config' && method === 'GET') {
                    return jsonResponse({ turnstileSiteKey: env.TURNSTILE_SITE_KEY });
                }

                const cookieHeader = request.headers.get('Cookie');
                let sessionIdFromCookie = null;
                if (cookieHeader) {
                    const authCookieString = cookieHeader.split(';').find(row => row.trim().startsWith('AuthToken='));
                    if (authCookieString) sessionIdFromCookie = authCookieString.split('=')[1]?.trim();
                }

                if (method === 'POST' && path === '/api/logout') {
                    return handleLogout(request, env, sessionIdFromCookie, url.hostname);
                }

                let userEmailFromSession = null;
                const authenticatedRoutes = [
                    '/api/me', 
                    '/api/change-password', 
                    '/api/update-profile',
                    '/api/2fa/', 
                    '/api/paste-keys', 
                    '/api/cloudpc-key',
                    '/api/oauth/clients',
                    '/api/messages', // 新增：私信相关路由需要认证
                    '/api/conversations',
                    '/api/messages/unread-count' 
                ];
                
                let needsAuth = authenticatedRoutes.some(p => {
                    if (p.endsWith('/')) {
                        return path.startsWith(p);
                    }
                    return path === p;
                });
                
                const oauthClientSpecificPathMatchForAuth = path.match(/^\/api\/oauth\/clients\/([\w-]+)$/);
                if (oauthClientSpecificPathMatchForAuth && (method === 'PUT' || method === 'DELETE')) {
                    needsAuth = true;
                }
                // 私信特定对话的路由也需要认证
                const conversationSpecificPathMatch = path.match(/^\/api\/conversations\/([\w-]+)(\/messages|\/read)?$/);
                if (conversationSpecificPathMatch) {
                    needsAuth = true;
                }


                if (needsAuth) {
                    userEmailFromSession = await authenticateApiRequest(sessionIdFromCookie, env);
                    if (!userEmailFromSession) {
                        console.warn(`[${rayId}][AUTH_FAIL] Unauthorized access attempt to ${path}. Session ID: ${sessionIdFromCookie}`);
                        return jsonResponse({ error: '未授权或会话无效' }, 401);
                    }
                    console.log(`[${rayId}][AUTH_SUCCESS] User ${userEmailFromSession} authenticated for ${path}`);
                }

                // 公共 API 路由
                if (method === 'POST' && path === '/api/register') {
                    return handleRegister(request, env, request.headers.get('CF-Connecting-IP'));
                }
                if (method === 'POST' && path === '/api/login') {
                    return handleLogin(request, env, url.protocol, url.hostname, request.headers.get('CF-Connecting-IP'));
                }
                if (method === 'POST' && path === '/api/login/2fa-verify') {
                    return handleLogin2FAVerify(request, env, url.protocol, url.hostname);
                }

                // 受保护的 API 路由
                if (path === '/api/me' && method === 'GET') {
                    if (!userEmailFromSession && needsAuth) return jsonResponse({ error: '未授权访问 /api/me' }, 401);
                    return handleGetMe(request, env, userEmailFromSession);
                }
                // ... (其他已有的受保护API路由保持不变) ...
                if (path === '/api/change-password' && method === 'POST') {
                    if (!userEmailFromSession) return jsonResponse({ error: '未授权访问 /api/change-password' }, 401);
                    return handleChangePassword(request, env, userEmailFromSession);
                }
                if (path === '/api/update-profile' && method === 'POST') {
                    if (!userEmailFromSession) return jsonResponse({ error: '未授权访问 /api/update-profile' }, 401);
                    return handleUpdateProfile(request, env, userEmailFromSession);
                }
                if (path.startsWith('/api/2fa/')) {
                    if (!userEmailFromSession) return jsonResponse({ error: '未授权访问 /api/2fa/ 功能' }, 401);
                    if (path === '/api/2fa/generate-secret' && method === 'GET') {
                        return handle2FAGenerateSecret(request, env, userEmailFromSession);
                    }
                    if (path === '/api/2fa/enable' && method === 'POST') {
                        return handle2FAEnable(request, env, userEmailFromSession);
                    }
                    if (path === '/api/2fa/disable' && method === 'POST') {
                        return handle2FADisable(request, env, userEmailFromSession);
                    }
                }
                if (path === '/api/paste-keys' && method === 'POST') {
                    if (!userEmailFromSession) return jsonResponse({ error: '未授权访问 /api/paste-keys' }, 401);
                    return handleCreatePasteApiKey(request, env, userEmailFromSession, request.headers.get('CF-Connecting-IP'));
                }
                if (path.startsWith('/api/cloudpc-key')) {
                    if (!userEmailFromSession) return jsonResponse({ error: '未授权访问 /api/cloudpc-key' }, 401);
                     if (method === 'GET') {
                        return handleGetCloudPcKey(request, env, userEmailFromSession);
                    }
                    if (method === 'POST') {
                        return handleCreateCloudPcKey(request, env, userEmailFromSession, request.headers.get('CF-Connecting-IP'));
                    }
                }
                // OAuth Client Management Endpoints
                if (path === '/api/oauth/clients') {
                    if (!userEmailFromSession) return jsonResponse({ error: '未授权访问 /api/oauth/clients' }, 401);
                    if (method === 'POST') { 
                        return handleRegisterOauthClient(request, env, userEmailFromSession);
                    }
                    if (method === 'GET') { 
                        return handleListOauthClients(request, env, userEmailFromSession);
                    }
                }
                
                const oauthClientSpecificPathMatch = path.match(/^\/api\/oauth\/clients\/([\w-]+)$/);
                if (oauthClientSpecificPathMatch) {
                    if (!userEmailFromSession) return jsonResponse({ error: '未授权访问 OAuth 客户端详情操作' }, 401);
                    const clientIdFromPath = oauthClientSpecificPathMatch[1];
                    if (method === 'PUT') {
                        return handleUpdateOauthClient(request, env, userEmailFromSession, clientIdFromPath);
                    }
                    if (method === 'DELETE') {
                        return handleDeleteOauthClient(request, env, userEmailFromSession, clientIdFromPath);
                    }
                }

                // --- 新增：私信 API 路由 ---
                if (path === '/api/messages' && method === 'POST') {
                    if (!userEmailFromSession) return jsonResponse({ error: '发送消息需要认证' }, 401);
                    return handleSendMessage(request, env, userEmailFromSession);
                }
                if (path === '/api/conversations' && method === 'GET') {
                    if (!userEmailFromSession) return jsonResponse({ error: '获取对话列表需要认证' }, 401);
                    return handleGetConversations(request, env, userEmailFromSession);
                }
                if (conversationSpecificPathMatch) { // 匹配 /api/conversations/:id/messages 或 /api/conversations/:id/read
                    if (!userEmailFromSession) return jsonResponse({ error: '访问对话需要认证' }, 401);
                    const conversationId = conversationSpecificPathMatch[1];
                    const actionPath = conversationSpecificPathMatch[2]; // 会是 "/messages", "/read", 或者 undefined

                    if (actionPath === '/messages' && method === 'GET') {
                        return handleGetMessagesForConversation(request, env, userEmailFromSession, conversationId);
                    }
                    if (actionPath === '/read' && method === 'POST') { // 将对话标记为已读
                        return handleMarkConversationAsRead(request, env, userEmailFromSession, conversationId);
                    }
                }
                if (path === '/api/messages/unread-count' && method === 'GET') {
                    if (!userEmailFromSession) return jsonResponse({ error: '获取未读消息数需要认证' }, 401);
                    return handleGetUnreadMessageCount(request, env, userEmailFromSession);
                }


                console.warn(`[${rayId}][ROUTE_MISS_API] Unhandled /api/ path: ${path} for method ${method}`);
                return jsonResponse({ error: 'API 端点未找到或请求方法不允许' }, 404);
            }

            // --- HTML UI 服务 ---
            if (method === 'GET' && (path === '/' || path === '/user/login' || path === '/user/register' || path === '/user/account')) {
                console.log(`[${rayId}][ROUTE_MATCH] HTML UI for path: ${path}`);
                return new Response(generateHtmlUi(path, env), { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
            }

            // --- 默认 404 ---
            console.warn(`[${rayId}][ROUTE_NOMATCH_404] Unhandled request: ${method} ${path}`);
            let errorPageIssuerUrl = '/';
             try { errorPageIssuerUrl = OAUTH_ISSUER_URL(env, request); } catch(e) { /* ignore */ }
            return new Response(generateErrorPageHtml({title: "页面未找到", message: `请求的资源 ${path} 不存在。`, issuerUrl: errorPageIssuerUrl, env}), { status: 404, headers: { 'Content-Type': 'text/html;charset=UTF-8' }});

        } catch (error) {
            console.error(`[${rayId}][WORKER_ERROR] Uncaught exception at path ${path}:`, error.message, error.stack, error);
            let errorPageIssuerUrl = '/';
            try { errorPageIssuerUrl = OAUTH_ISSUER_URL(env, request); } catch (e) { /* ignore */ }
            return new Response(generateErrorPageHtml({title: "服务器内部错误", message: "处理您的请求时发生意外错误。", issuerUrl: errorPageIssuerUrl, env}), { status: 500, headers: { 'Content-Type': 'text/html;charset=UTF-8' }});
        }
    },
};
