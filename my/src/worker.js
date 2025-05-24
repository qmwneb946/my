export class ConversationDurableObject {
    constructor(state, env) {
        this.state = state;
        this.env = env;
        this.sessions = [];
        this.allMessages = [];
        this.conversationId = null;
        this.participants = [];
        this.initialized = false;
        this.pageSize = 20;
        this.state.blockConcurrencyWhile(async () => {
            let stored = await this.state.storage.get(["conversationId", "participants", "allMessages"]);
            this.conversationId = stored.get("conversationId");
            this.participants = stored.get("participants") || [];
            this.allMessages = stored.get("allMessages") || [];
            if (this.conversationId && this.participants.length > 0) {
                this.initialized = true;
                if (this.allMessages.length === 0 && this.env.DB) {
                    await this.loadAllMessagesFromD1();
                }
            }
        });
    }
    async loadAllMessagesFromD1() {
        if (!this.env.DB || !this.conversationId) return;
        try {
            const { results } = await this.env.DB.prepare(
                `SELECT m.message_id, m.conversation_id, m.sender_email, u_sender.username as sender_username, m.content, m.sent_at, m.is_read
                 FROM messages m
                 JOIN users u_sender ON m.sender_email = u_sender.email
                 WHERE m.conversation_id = ?
                 ORDER BY m.sent_at ASC`
            ).bind(this.conversationId).all();
            if (results) {
                this.allMessages = results;
                await this.state.storage.put("allMessages", this.allMessages);
            }
        } catch (e) {
        }
    }
    async initialize(conversationId, participant1Email, participant2Email) {
        if (this.initialized) return;
        this.conversationId = conversationId;
        this.participants = [participant1Email, participant2Email].sort();
        await this.loadAllMessagesFromD1();
        await this.state.storage.put({
            "conversationId": this.conversationId,
            "participants": this.participants,
            "allMessages": this.allMessages
        });
        this.initialized = true;
    }
    static getConversationDOName(user1Email, user2Email) {
        const participants = [user1Email, user2Email].sort();
        return `conv-${participants[0]}-${participants[1]}`;
    }
    async fetch(request) {
        const url = new URL(request.url);
        const userEmail = request.headers.get("X-User-Email");
        const requestD1ConversationId = request.headers.get("X-Conversation-D1-Id");
        const requestP1 = request.headers.get("X-Participant1-Email");
        const requestP2 = request.headers.get("X-Participant2-Email");
        if (!this.initialized && requestD1ConversationId && requestP1 && requestP2) {
            await this.initialize(requestD1ConversationId, requestP1, requestP2);
        }
        if (!this.initialized) {
            return new Response("DO 未初始化。请调用 /initialize 或提供头部信息。", { status: 500 });
        }
        if (!userEmail) {
            return new Response("需要 X-User-Email 头部信息。", { status: 400 });
        }
        if (!this.participants.includes(userEmail)) {
             return new Response("禁止访问：用户不是参与者。", { status: 403 });
        }
        if (url.pathname === "/websocket") {
            if (request.headers.get("Upgrade") !== "websocket") {
                return new Response("期望 WebSocket 升级", { status: 426 });
            }
            const pair = new WebSocketPair();
            const [client, server] = Object.values(pair);
            server.accept();
            this.sessions.push({ ws: server, userEmail: userEmail, lastSentMessageIndex: this.allMessages.length });
            const initialMessagesToSend = this.allMessages.slice(-this.pageSize);
            initialMessagesToSend.forEach(msg => {
                server.send(JSON.stringify({ type: "HISTORICAL_MESSAGE", data: msg }));
            });
            if (this.allMessages.length > this.pageSize) {
                server.send(JSON.stringify({ type: "MORE_MESSAGES_AVAILABLE", data: { oldestMessageTimestamp: this.allMessages[0].sent_at } }));
            }
            server.send(JSON.stringify({ type: "CONNECTION_ESTABLISHED", data: { conversationId: this.conversationId, participants: this.participants }}));
            server.addEventListener("message", async event => {
                try {
                    const messageData = JSON.parse(event.data);
                    if (messageData.type === "REQUEST_MORE_MESSAGES") {
                        const currentSession = this.sessions.find(s => s.ws === server);
                        if (currentSession) {
                            const currentOldestLoadedIndex = currentSession.lastSentMessageIndex - initialMessagesToSend.length;
                            const nextBatchStartIndex = Math.max(0, currentOldestLoadedIndex - this.pageSize);
                            const messagesToLoad = this.allMessages.slice(nextBatchStartIndex, currentOldestLoadedIndex);
                            messagesToLoad.reverse().forEach(msg => {
                                server.send(JSON.stringify({ type: "HISTORICAL_MESSAGE", data: msg, prepended: true }));
                            });
                            currentSession.lastSentMessageIndex = nextBatchStartIndex;
                            if (nextBatchStartIndex > 0) {
                                server.send(JSON.stringify({ type: "MORE_MESSAGES_AVAILABLE", data: { oldestMessageTimestamp: this.allMessages[0].sent_at } }));
                            } else {
                                server.send(JSON.stringify({ type: "NO_MORE_MESSAGES" }));
                            }
                        }
                    } else if (messageData.type === "NEW_MESSAGE") {
                        const { content } = messageData.data;
                        const senderEmail = userEmail;
                        const receiverEmail = this.participants.find(p => p !== senderEmail);
                        if (!receiverEmail) {
                             server.send(JSON.stringify({ type: "ERROR", data: "无法确定接收者。"}));
                             return;
                        }
                        const now = Date.now();
                        const messageId = crypto.randomUUID();
                        let senderUsername = senderEmail.split('@')[0];
                        try {
                            const userDetails = await this.env.DB.prepare("SELECT username FROM users WHERE email = ?").bind(senderEmail).first();
                            if (userDetails && userDetails.username) senderUsername = userDetails.username;
                        } catch (e) {  }
                        const newMessage = {
                            message_id: messageId,
                            conversation_id: this.conversationId,
                            sender_email: senderEmail,
                            sender_username: senderUsername,
                            content: content,
                            sent_at: now,
                            is_read: 0,
                        };
                        if (this.env.DB) {
                            try {
                                await this.env.DB.prepare(
                                    "INSERT INTO messages (message_id, conversation_id, sender_email, receiver_email, content, sent_at, is_read) VALUES (?, ?, ?, ?, ?, ?, 0)"
                                ).bind(messageId, this.conversationId, senderEmail, receiverEmail, content, now).run();
                                await this.env.DB.prepare("UPDATE conversations SET last_message_at = ? WHERE conversation_id = ?")
                                    .bind(now, this.conversationId).run();
                            } catch (e) {
                                server.send(JSON.stringify({ type: "ERROR", data: "保存消息失败。" }));
                                return;
                            }
                        }
                        this.allMessages.push(newMessage);
                        await this.state.storage.put("allMessages", this.allMessages);
                        this.sessions.forEach(s => {
                            if (s.ws.readyState === WebSocket.OPEN) {
                                s.lastSentMessageIndex = this.allMessages.length;
                            }
                        });
                        this.broadcast({ type: "NEW_MESSAGE", data: newMessage });
                        if (this.env.USER_PRESENCE_DO) {
                            try {
                                const presenceDOId = this.env.USER_PRESENCE_DO.idFromName(`user-${receiverEmail}`);
                                const presenceStub = this.env.USER_PRESENCE_DO.get(presenceDOId);
                                await presenceStub.fetch(new Request(`https://do-internal/updateConversationState`, {
                                    method: 'POST',
                                    headers: {'Content-Type': 'application/json'},
                                    body: JSON.stringify({
                                        conversationId: this.conversationId,
                                        action: 'newMessage',
                                        senderEmail: senderEmail,
                                        messageTimestamp: now,
                                        messageContent: content,
                                        otherParticipantEmail: senderEmail,
                                        otherParticipantUsername: senderUsername
                                    })
                                }));
                            } catch(e) {  }
                            try {
                                const senderPresenceDOId = this.env.USER_PRESENCE_DO.idFromName(`user-${senderEmail}`);
                                const senderPresenceStub = this.env.USER_PRESENCE_DO.get(senderPresenceDOId);
                                await senderPresenceStub.fetch(new Request(`https://do-internal/updateConversationState`, {
                                    method: 'POST',
                                    headers: {'Content-Type': 'application/json'},
                                    body: JSON.stringify({
                                        conversationId: this.conversationId,
                                        action: 'messageSent',
                                        receiverEmail: receiverEmail,
                                        messageTimestamp: now,
                                        messageContent: content,
                                    })
                                }));
                            } catch(e) {  }
                        }
                    } else if (messageData.type === "MESSAGE_SEEN") {
                        const { message_id: seenMessageId } = messageData.data;
                        if (this.env.DB && this.conversationId) {
                           const messagesRead = await this.env.DB.prepare(
                                "UPDATE messages SET is_read = 1 WHERE conversation_id = ? AND receiver_email = ? AND is_read = 0"
                            ).bind(this.conversationId, userEmail).run();
                            this.allMessages.forEach(msg => {
                                if (msg.receiver_email === userEmail && msg.conversation_id === this.conversationId && !msg.is_read) {
                                     msg.is_read = 1;
                                }
                            });
                            await this.state.storage.put("allMessages", this.allMessages);
                            this.broadcast({ type: "MESSAGES_READ", data: { reader: userEmail, conversationId: this.conversationId, count: messagesRead.meta.changes }});
                             if (this.env.USER_PRESENCE_DO) {
                                try {
                                    const presenceDOId = this.env.USER_PRESENCE_DO.idFromName(`user-${userEmail}`);
                                    const presenceStub = this.env.USER_PRESENCE_DO.get(presenceDOId);
                                    await presenceStub.fetch(new Request(`https://do-internal/updateConversationState`, {
                                        method: 'POST',
                                        headers: {'Content-Type': 'application/json'},
                                        body: JSON.stringify({ conversationId: this.conversationId, action: 'markRead' })
                                    }));
                                } catch(e) {  }
                            }
                        }
                    }
                } catch (e) {
                    server.send(JSON.stringify({ type: "ERROR", data: "无效的消息格式或处理错误。" }));
                }
            });
            server.addEventListener("close", () => {
                this.sessions = this.sessions.filter(s => s.ws !== server);
            });
            server.addEventListener("error", (err) => {
                this.sessions = this.sessions.filter(s => s.ws !== server);
            });
            return new Response(null, { status: 101, webSocket: client });
        } else if (url.pathname === "/initialize" && request.method === "POST") {
            try {
                const { conversationId, participant1Email, participant2Email } = await request.json();
                if (conversationId && participant1Email && participant2Email) {
                    if (!this.initialized) {
                        await this.initialize(conversationId, participant1Email, participant2Email);
                    }
                    return new Response("DO 已初始化或之前已初始化", { status: 200 });
                }
                return new Response("DO初始化缺少数据", { status: 400 });
            } catch (e) {
                return new Response(`DO初始化错误: ${e.message}`, { status: 500 });
            }
        }
        return new Response("在ConversationDurableObject中未找到", { status: 404 });
    }
    broadcast(message) {
        const serializedMessage = JSON.stringify(message);
        this.sessions = this.sessions.filter(session => {
            try {
                if (session.ws.readyState === WebSocket.OPEN) {
                    session.ws.send(serializedMessage);
                    return true;
                } else {
                    return false;
                }
            } catch (e) {
                return false;
            }
        });
    }
}
export class UserPresenceDurableObject {
    constructor(state, env) {
        this.state = state;
        this.env = env;
        this.userEmail = null;
        this.webSocket = null;
        this.conversationsSummary = {};
        this.initialized = false;
        this.state.blockConcurrencyWhile(async () => {
            const storedUserEmail = await this.state.storage.get("userEmail");
            if (storedUserEmail) {
                this.userEmail = storedUserEmail;
                const storedSummary = await this.state.storage.get("conversationsSummary");
                if (storedSummary) {
                    this.conversationsSummary = storedSummary;
                }
                this.initialized = true;
            }
        });
    }
    async initialize(userEmail) {
        if (this.initialized && this.userEmail === userEmail) return;
        this.userEmail = userEmail;
        await this.state.storage.put("userEmail", this.userEmail);
        await this.fetchConversationsSummaryFromD1();
        this.initialized = true;
    }
    async fetchConversationsSummaryFromD1() {
        if (!this.userEmail || !this.env.DB) return;
        try {
            const convResults = await this.env.DB.prepare(
                 `SELECT
                    c.conversation_id, c.last_message_at, c.participant1_email, c.participant2_email,
                    u1.username as p1_username, u2.username as p2_username,
                    (SELECT COUNT(*) FROM messages m WHERE m.conversation_id = c.conversation_id AND m.receiver_email = ?1 AND m.is_read = 0) as unread_count,
                    (SELECT content FROM messages m WHERE m.conversation_id = c.conversation_id ORDER BY m.sent_at DESC LIMIT 1) as last_message_content,
                    (SELECT sender_email FROM messages m WHERE m.conversation_id = c.conversation_id ORDER BY m.sent_at DESC LIMIT 1) as last_message_sender
                  FROM conversations c
                  LEFT JOIN users u1 ON c.participant1_email = u1.email
                  LEFT JOIN users u2 ON c.participant2_email = u2.email
                  WHERE c.participant1_email = ?1 OR c.participant2_email = ?1
                  ORDER BY c.last_message_at DESC`
            ).bind(this.userEmail).all();
            const newSummary = {};
            let totalUnread = 0;
            if (convResults && convResults.results) {
                convResults.results.forEach(conv => {
                    const otherParticipantEmail = conv.participant1_email === this.userEmail ? conv.participant2_email : conv.participant1_email;
                    const otherParticipantUsername = conv.participant1_email === this.userEmail ? conv.p2_username : conv.p1_username;
                    newSummary[conv.conversation_id] = {
                        conversation_id: conv.conversation_id,
                        unread_count: conv.unread_count || 0,
                        last_message_at: conv.last_message_at,
                        last_message_content: conv.last_message_content,
                        last_message_sender: conv.last_message_sender,
                        other_participant_email: otherParticipantEmail,
                        other_participant_username: otherParticipantUsername || otherParticipantEmail.split('@')[0],
                    };
                    totalUnread += (conv.unread_count || 0);
                });
            }
            this.conversationsSummary = newSummary;
            await this.state.storage.put("conversationsSummary", this.conversationsSummary);
            if (this.webSocket && this.webSocket.readyState === WebSocket.OPEN) {
                this.webSocket.send(JSON.stringify({ type: "CONVERSATIONS_LIST", data: Object.values(this.conversationsSummary) }));
                this.webSocket.send(JSON.stringify({ type: "UNREAD_COUNT_TOTAL", data: { unread_count: totalUnread } }));
            }
        } catch (e) {
        }
    }
    async fetch(request) {
        const url = new URL(request.url);
        const requestUserEmail = request.headers.get("X-User-Email");
        if (!this.initialized && requestUserEmail) {
            await this.initialize(requestUserEmail);
        } else if (!this.initialized && this.state.id && this.state.id.name && this.state.id.name.startsWith("user-")) {
            await this.initialize(this.state.id.name.substring(5));
        }
        if (!this.initialized || !this.userEmail) {
             return new Response("UserPresenceDO 未正确初始化。", { status: 500 });
        }
        if (url.pathname === "/websocket") {
            if (request.headers.get("Upgrade") !== "websocket") {
                return new Response("期望 WebSocket 升级", { status: 426 });
            }
            if (this.webSocket && this.webSocket.readyState === WebSocket.OPEN) {
                this.webSocket.close(1000, "新连接已建立");
            }
            const pair = new WebSocketPair();
            const [client, server] = Object.values(pair);
            this.webSocket = server;
            this.webSocket.accept();
            await this.fetchConversationsSummaryFromD1();
            this.webSocket.addEventListener("message", async event => {
                try {
                    const messageData = JSON.parse(event.data);
                    if (messageData.type === "REQUEST_INITIAL_STATE" || messageData.type === "REQUEST_CONVERSATIONS_LIST") {
                        await this.fetchConversationsSummaryFromD1();
                    }
                } catch(e) {
                }
            });
            this.webSocket.addEventListener("close", () => { this.webSocket = null; });
            this.webSocket.addEventListener("error", (err) => {
                this.webSocket = null;
            });
            return new Response(null, { status: 101, webSocket: client });
        } else if (url.pathname === "/updateConversationState" && request.method === "POST") {
            const updateData = await request.json();
            const { conversationId, action, senderEmail, messageTimestamp, messageContent, otherParticipantEmail, otherParticipantUsername, receiverEmail } = updateData;
            let changed = false;
            if (!this.conversationsSummary[conversationId]) {
                 this.conversationsSummary[conversationId] = {
                    conversation_id: conversationId,
                    unread_count: 0,
                    last_message_at: 0,
                    last_message_content: "",
                    last_message_sender: "",
                    other_participant_email: action === 'newMessage' ? (otherParticipantEmail || senderEmail) : (action === 'messageSent' ? receiverEmail : ""),
                    other_participant_username: action === 'newMessage' ? (otherParticipantUsername || (otherParticipantEmail || senderEmail || "").split('@')[0]) : (action === 'messageSent' ? (receiverEmail || "").split('@')[0] : "")
                };
                changed = true;
            }
            const currentConv = this.conversationsSummary[conversationId];
            if (action === 'newMessage') {
                currentConv.unread_count = (currentConv.unread_count || 0) + 1;
                currentConv.last_message_at = messageTimestamp;
                currentConv.last_message_content = messageContent;
                currentConv.last_message_sender = senderEmail;
                if (!currentConv.other_participant_email && senderEmail) {
                    currentConv.other_participant_email = senderEmail;
                    currentConv.other_participant_username = otherParticipantUsername || senderEmail.split('@')[0];
                }
                changed = true;
            } else if (action === 'markRead') {
                if (currentConv.unread_count > 0) {
                    currentConv.unread_count = 0;
                    changed = true;
                }
            } else if (action === 'messageSent') {
                currentConv.last_message_at = messageTimestamp;
                currentConv.last_message_content = messageContent;
                currentConv.last_message_sender = this.userEmail;
                 if (!currentConv.other_participant_email && receiverEmail) {
                    currentConv.other_participant_email = receiverEmail;
                    currentConv.other_participant_username = receiverEmail.split('@')[0];
                }
                changed = true;
            }
            if (changed) {
                await this.state.storage.put("conversationsSummary", this.conversationsSummary);
                let totalUnread = 0;
                Object.values(this.conversationsSummary).forEach(conv => totalUnread += (conv.unread_count || 0));
                if (this.webSocket && this.webSocket.readyState === WebSocket.OPEN) {
                    const sortedSummary = Object.values(this.conversationsSummary).sort((a,b) => (b.last_message_at || 0) - (a.last_message_at || 0));
                    this.webSocket.send(JSON.stringify({ type: "CONVERSATIONS_LIST", data: sortedSummary }));
                    this.webSocket.send(JSON.stringify({ type: "UNREAD_COUNT_TOTAL", data: { unread_count: totalUnread } }));
                }
            }
            return new Response("用户状态已更新", { status: 200 });
        } else if (url.pathname === "/getConversationsList" && request.method === "GET") {
            await this.fetchConversationsSummaryFromD1();
            const sortedSummary = Object.values(this.conversationsSummary).sort((a,b) => (b.last_message_at || 0) - (a.last_message_at || 0));
            return new Response(JSON.stringify(sortedSummary), { headers: { 'Content-Type': 'application/json'}});
        } else if (url.pathname === "/getTotalUnreadCount" && request.method === "GET") {
            await this.fetchConversationsSummaryFromD1();
            let totalUnread = 0;
            Object.values(this.conversationsSummary).forEach(conv => totalUnread += (conv.unread_count || 0));
            return new Response(JSON.stringify({ unread_count: totalUnread }), { headers: { 'Content-Type': 'application/json'}});
        }
        return new Response("在UserPresenceDurableObject中未找到", { status: 404 });
    }
}
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
    handleGetGreenHubKeys,
    handleAdminListUsers,
    handleAdminGetUser,
    handleAdminUpdateUser,
    handleAdminListOauthClients,
    handleAdminGetOauthClient,
    handleAdminUpdateOauthClient,
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
import { generateHtmlUi, generateErrorPageHtml, generateHelpPageHtml } from './html-ui.js';
import { jsonResponse, OAUTH_ISSUER_URL, isAdminUser } from './helpers.js';
export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        const path = url.pathname;
        const method = request.method;
        const rayId = request.headers.get('cf-ray') || crypto.randomUUID();
        let userEmailFromSession = null;
        const cookieHeader = request.headers.get('Cookie');
        let sessionIdFromCookie = null;
        if (cookieHeader) {
            const authCookieString = cookieHeader.split(';').find(row => row.trim().startsWith('AuthToken='));
            if (authCookieString) sessionIdFromCookie = authCookieString.split('=')[1]?.trim();
        }
        if (sessionIdFromCookie && env.DB) {
             userEmailFromSession = await authenticateApiRequest(sessionIdFromCookie, env);
        }
        const uiPaths = [
            '/',
            '/user/login',
            '/user/register',
            '/user/profile',
            '/user/security',
            '/user/api-keys',
            '/user/applications',
            '/user/messaging',
            '/user/admin',
            '/user/admin/users',
            '/user/admin/apps'
        ];
        try {
            if (method === 'GET' && path === '/user/account') {
                return Response.redirect(`${url.origin}/user/profile`, 302);
            }
            if (method === 'GET' && uiPaths.includes(path)) {
                return new Response(generateHtmlUi(path, env), { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
            }
            if (method === 'GET' && path === '/.well-known/openid-configuration') {
                return handleOpenIDConfiguration(request, env);
            }
            if (method === 'GET' && path === '/.well-known/jwks.json') {
                return handleJwks(request, env);
            }
            if (path.startsWith('/oauth/')) {
                if (path === '/oauth/authorize') {
                    return handleOAuthAuthorize(request, env);
                }
                if (path === '/oauth/token' && method === 'POST') {
                    return handleOAuthToken(request, env);
                }
                if (path === '/oauth/userinfo' && (method === 'GET' || method === 'POST')) {
                    return handleOAuthUserInfo(request, env);
                }
                return jsonResponse({ error: 'OAuth/OIDC 端点未找到或方法不允许' }, 404);
            }
            if (path.startsWith('/api/ws/user')) {
                if (!userEmailFromSession) return jsonResponse({ error: 'WebSocket 需要身份验证' }, 401);
                const doId = env.USER_PRESENCE_DO.idFromName(`user-${userEmailFromSession}`);
                const stub = env.USER_PRESENCE_DO.get(doId);
                const forwardRequestHeaders = new Headers(request.headers);
                forwardRequestHeaders.set('X-User-Email', userEmailFromSession);
                return stub.fetch(new Request(`${url.origin}/websocket`, new Request(request, {headers: forwardRequestHeaders})));
            }
            const wsConversationMatch = path.match(/^\/api\/ws\/conversation\/([a-fA-F0-9-]+)$/);
            if (wsConversationMatch) {
                if (!userEmailFromSession) return jsonResponse({ error: 'WebSocket 需要身份验证' }, 401);
                const conversationD1Id = wsConversationMatch[1];
                const convDetails = await env.DB.prepare(
                    "SELECT participant1_email, participant2_email FROM conversations WHERE conversation_id = ?"
                ).bind(conversationD1Id).first();
                if (!convDetails) return jsonResponse({ error: '对话未找到' }, 404);
                if (userEmailFromSession !== convDetails.participant1_email && userEmailFromSession !== convDetails.participant2_email) {
                    return jsonResponse({ error: '禁止访问' }, 403);
                }
                const doName = ConversationDurableObject.getConversationDOName(convDetails.participant1_email, convDetails.participant2_email);
                const doId = env.CONVERSATION_DO.idFromName(doName);
                const stub = env.CONVERSATION_DO.get(doId);
                const forwardRequestHeaders = new Headers(request.headers);
                forwardRequestHeaders.set('X-User-Email', userEmailFromSession);
                forwardRequestHeaders.set('X-Conversation-D1-Id', conversationD1Id);
                forwardRequestHeaders.set('X-Participant1-Email', convDetails.participant1_email);
                forwardRequestHeaders.set('X-Participant2-Email', convDetails.participant2_email);
                return stub.fetch(new Request(`${url.origin}/websocket`, new Request(request, {headers: forwardRequestHeaders})));
            }
            if (path.startsWith('/api/')) {
                if (path === '/api/config' && method === 'GET') {
                    return jsonResponse({ turnstileSiteKey: env.TURNSTILE_SITE_KEY });
                }
                if (method === 'POST' && path === '/api/logout') {
                    return handleLogout(request, env, sessionIdFromCookie, url.hostname);
                }
                const authenticatedRoutes = [
                    '/api/me', '/api/change-password', '/api/update-profile',
                    '/api/2fa/', '/api/paste-keys', '/api/cloudpc-key',
                    '/api/greenhub-keys', '/api/oauth/clients', '/api/messages', '/api/conversations',
                    '/api/admin/'
                ];
                let needsAuth = authenticatedRoutes.some(p => path.startsWith(p) || (p.endsWith('/') && path.startsWith(p.slice(0,-1))) || path === p );
                const oauthClientSpecificPathMatchForAuth = path.match(/^\/api\/oauth\/clients\/([\w-]+)$/);
                if (oauthClientSpecificPathMatchForAuth && (method === 'PUT' || method === 'DELETE')) {
                    needsAuth = true;
                }
                if (needsAuth && !userEmailFromSession) {
                    return jsonResponse({ error: '未授权或会话无效' }, 401);
                }
                if (path.startsWith('/api/admin/')) {
                    if (!isAdminUser(userEmailFromSession, env)) {
                        return jsonResponse({ error: '禁止访问管理员接口' }, 403);
                    }
                    if (path === '/api/admin/users' && method === 'GET') {
                        return handleAdminListUsers(request, env);
                    }
                    const adminUserEmailRegex = /^\/api\/admin\/users\/([^/]+)$/; // Simplified regex
                    const adminUserDetailMatch = path.match(adminUserEmailRegex);
                    if (adminUserDetailMatch) {
                        const targetUserEmail = decodeURIComponent(adminUserDetailMatch[1]);
                        if (method === 'GET') {
                            return handleAdminGetUser(request, env, targetUserEmail);
                        } else if (method === 'PUT') {
                            return handleAdminUpdateUser(request, env, targetUserEmail);
                        } else {
                            return jsonResponse({ error: `方法 ${method} 不允许用于此用户管理端点` }, 405);
                        }
                    }
                    if (path === '/api/admin/oauth/clients' && method === 'GET') {
                        return handleAdminListOauthClients(request, env);
                    }
                    const adminClientDetailMatch = path.match(/^\/api\/admin\/oauth\/clients\/([\w-]+)$/);
                    if (adminClientDetailMatch) {
                        const targetClientId = adminClientDetailMatch[1];
                        if (method === 'GET') {
                            return handleAdminGetOauthClient(request, env, targetClientId);
                        } else if (method === 'PUT') {
                            return handleAdminUpdateOauthClient(request, env, targetClientId);
                        } else {
                             return jsonResponse({ error: `方法 ${method} 不允许用于此应用管理端点` }, 405);
                        }
                    }
                    return jsonResponse({ error: '管理员 API 端点未找到' }, 404);
                }
                if (method === 'POST' && path === '/api/register') {
                    return handleRegister(request, env, request.headers.get('CF-Connecting-IP'));
                }
                if (method === 'POST' && path === '/api/login') {
                    return handleLogin(request, env, url.protocol, url.hostname, request.headers.get('CF-Connecting-IP'));
                }
                if (method === 'POST' && path === '/api/login/2fa-verify') {
                    return handleLogin2FAVerify(request, env, url.protocol, url.hostname);
                }
                if (path === '/api/me' && method === 'GET') {
                    return handleGetMe(request, env, userEmailFromSession);
                }
                if (path === '/api/change-password' && method === 'POST') {
                    return handleChangePassword(request, env, userEmailFromSession);
                }
                if (path === '/api/update-profile' && method === 'POST') {
                    return handleUpdateProfile(request, env, userEmailFromSession);
                }
                if (path.startsWith('/api/2fa/')) {
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
                    return handleCreatePasteApiKey(request, env, userEmailFromSession, request.headers.get('CF-Connecting-IP'));
                }
                if (path.startsWith('/api/cloudpc-key')) {
                     if (method === 'GET') {
                        return handleGetCloudPcKey(request, env, userEmailFromSession);
                    }
                    if (method === 'POST') {
                        return handleCreateCloudPcKey(request, env, userEmailFromSession, request.headers.get('CF-Connecting-IP'));
                    }
                }
                if (path === '/api/greenhub-keys' && method === 'GET') {
                    return handleGetGreenHubKeys(request, env, userEmailFromSession);
                }
                if (path === '/api/oauth/clients') {
                    if (method === 'POST') {
                        return handleRegisterOauthClient(request, env, userEmailFromSession);
                    }
                    if (method === 'GET') {
                        return handleListOauthClients(request, env, userEmailFromSession);
                    }
                }
                if (oauthClientSpecificPathMatchForAuth) {
                    const clientIdFromPath = oauthClientSpecificPathMatchForAuth[1];
                    if (method === 'PUT') {
                        return handleUpdateOauthClient(request, env, userEmailFromSession, clientIdFromPath);
                    }
                    if (method === 'DELETE') {
                        return handleDeleteOauthClient(request, env, userEmailFromSession, clientIdFromPath);
                    }
                }
                if (path === '/api/messages' && method === 'POST') {
                    if (!userEmailFromSession) return jsonResponse({ error: '用户未认证' }, 401);
                    const reqBody = await request.json();
                    const { receiverEmail, content } = reqBody;
                    if (!receiverEmail || !content) return jsonResponse({ error: '接收者和内容为必填项' }, 400);
                    if (receiverEmail === userEmailFromSession) return jsonResponse({ error: '不能给自己发送消息' }, 400);
                    const receiverUser = await env.DB.prepare("SELECT email FROM users WHERE email = ?").bind(receiverEmail).first();
                    if (!receiverUser) return jsonResponse({ error: '接收用户不存在' }, 404);
                    const p1Sorted = [userEmailFromSession, receiverEmail].sort()[0];
                    const p2Sorted = [userEmailFromSession, receiverEmail].sort()[1];
                    let conversation = await env.DB.prepare(
                        "SELECT conversation_id FROM conversations WHERE participant1_email = ? AND participant2_email = ?"
                    ).bind(p1Sorted, p2Sorted).first();
                    let conversationD1Id;
                    if (!conversation) {
                        conversationD1Id = crypto.randomUUID();
                        const nowDb = Date.now();
                        await env.DB.prepare(
                            "INSERT INTO conversations (conversation_id, participant1_email, participant2_email, last_message_at, created_at) VALUES (?, ?, ?, ?, ?)"
                        ).bind(conversationD1Id, p1Sorted, p2Sorted, nowDb, nowDb).run();
                    } else {
                        conversationD1Id = conversation.conversation_id;
                    }
                    const doName = ConversationDurableObject.getConversationDOName(p1Sorted, p2Sorted);
                    const doId = env.CONVERSATION_DO.idFromName(doName);
                    const stub = env.CONVERSATION_DO.get(doId);
                    const initResponse = await stub.fetch(new Request(`${url.origin}/initialize`, {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json', 'X-User-Email': userEmailFromSession},
                        body: JSON.stringify({
                            conversationId: conversationD1Id,
                            participant1Email: p1Sorted,
                            participant2Email: p2Sorted
                        })
                    }));
                    if (!initResponse.ok) {
                    }
                    return jsonResponse({
                        success: true,
                        message: '对话已就绪。请通过WebSocket发送实际消息。',
                        conversationId: conversationD1Id
                    });
                }
                if (path === '/api/conversations' && method === 'GET') {
                    if (!userEmailFromSession) return jsonResponse({ error: '用户未认证' }, 401);
                    const doId = env.USER_PRESENCE_DO.idFromName(`user-${userEmailFromSession}`);
                    const stub = env.USER_PRESENCE_DO.get(doId);
                    const forwardRequestHeaders = new Headers(request.headers);
                    forwardRequestHeaders.set('X-User-Email', userEmailFromSession);
                    return stub.fetch(new Request(`${url.origin}/getConversationsList`, new Request(request, {headers: forwardRequestHeaders})));
                }
                if (path === '/api/messages/unread-count' && method === 'GET') {
                    if (!userEmailFromSession) return jsonResponse({ error: '用户未认证' }, 401);
                    const doId = env.USER_PRESENCE_DO.idFromName(`user-${userEmailFromSession}`);
                    const stub = env.USER_PRESENCE_DO.get(doId);
                    const forwardRequestHeaders = new Headers(request.headers);
                    forwardRequestHeaders.set('X-User-Email', userEmailFromSession);
                    return stub.fetch(new Request(`${url.origin}/getTotalUnreadCount`, new Request(request, {headers: forwardRequestHeaders})));
                }
                return jsonResponse({ error: 'API 端点未找到或请求方法不允许' }, 404);
            }
            if (method === 'GET' && path === '/user/help') {
                return new Response(generateHelpPageHtml(env), { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
            }
            let errorPageIssuerUrl = '/';
             try { errorPageIssuerUrl = OAUTH_ISSUER_URL(env, request); } catch(e) {  }
            return new Response(generateErrorPageHtml({title: "页面未找到", message: `请求的资源 ${path} 不存在。`, issuerUrl: errorPageIssuerUrl, env}), { status: 404, headers: { 'Content-Type': 'text/html;charset=UTF-8' }});
        } catch (error) {
            let errorPageIssuerUrl = '/';
            try { errorPageIssuerUrl = OAUTH_ISSUER_URL(env, request); } catch (e) {  }
            return new Response(generateErrorPageHtml({title: "服务器内部错误", message: "处理您的请求时发生意外错误。", issuerUrl: errorPageIssuerUrl, env}), { status: 500, headers: { 'Content-Type': 'text/html;charset=UTF-8' }});
        }
    },
};
