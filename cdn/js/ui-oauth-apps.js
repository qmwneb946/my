// 前端脚本 - “我的应用” (OAuth 客户端) 选项卡相关逻辑
// Frontend Script - "My Applications" (OAuth Clients) Tab Logic

// DOM 元素引用 (在 DOMContentLoaded 中或首次使用时获取)
let registerOauthClientForm, newOauthClientCredentialsDiv, newClientIdDisplay, newClientSecretDisplay;
let registeredOauthClientsListDiv;

/**
 * 初始化“我的应用”选项卡的数据。
 * 当选项卡被激活时由 main.js 中的 activateTab 调用。
 */
function loadOauthAppsTabData() {
    loadRegisteredOauthClients();
    // 确保注册表单中的 Turnstile 被渲染（如果可见）
    const oauthClientTurnstile = document.querySelector('#register-oauth-client-form .cf-turnstile');
    if (oauthClientTurnstile && oauthClientTurnstile.offsetParent !== null) { // 检查元素是否可见
        if (typeof renderTurnstile === 'function') renderTurnstile(oauthClientTurnstile);
    }
    // 注意：隐藏 newOauthClientCredentialsDiv 的逻辑现在主要由 main.js 中的 activateTab 处理
    // 此处不再重复隐藏，以避免在注册成功后立即隐藏凭据。
}

/**
 * 处理注册新的 OAuth 客户端应用表单提交。
 */
async function handleRegisterOauthClientSubmit(event) {
    event.preventDefault();
    if (typeof clearMessages === 'function') clearMessages();
    if (newOauthClientCredentialsDiv) newOauthClientCredentialsDiv.classList.add('hidden'); // 先隐藏旧的凭据显示

    const form = event.target;
    const turnstileContainer = form.querySelector('.cf-turnstile');
    const turnstileToken = form.querySelector('[name="cf-turnstile-response"]')?.value;

    if (!turnstileToken && turnstileContainer) {
        if (typeof showMessage === 'function') showMessage('人机验证失败，请重试。', 'error');
        if (typeof resetTurnstileInContainer === 'function') resetTurnstileInContainer(turnstileContainer);
        return;
    }

    const clientName = form.elements['clientName'].value;
    const clientWebsite = form.elements['clientWebsite'].value;
    const clientDescription = form.elements['clientDescription'].value;
    const redirectUri = form.elements['redirectUri'].value;

    // 前端基本验证
    if (!clientName || clientName.trim() === '') {
        if (typeof showMessage === 'function') showMessage('应用名称不能为空。', 'error');
        return;
    }
    if (!redirectUri || redirectUri.trim() === '') {
        if (typeof showMessage === 'function') showMessage('回调地址 (Redirect URI) 不能为空。', 'error');
        return;
    }
    try {
        const parsedRedirectUri = new URL(redirectUri.trim());
        if (parsedRedirectUri.protocol !== "https:") {
            if (typeof showMessage === 'function') showMessage('回调地址必须使用 HTTPS 协议。', 'error');
            return;
        }
    } catch (e) {
        if (typeof showMessage === 'function') showMessage('回调地址不是一个有效的 URL。', 'error');
        return;
    }

    const requestBody = { clientName, clientWebsite, clientDescription, redirectUri: redirectUri.trim(), turnstileToken };

    if (typeof apiCall === 'function') {
        const { ok, data, status } = await apiCall('/api/oauth/clients', 'POST', requestBody);
        if (turnstileContainer && typeof resetTurnstileInContainer === 'function') resetTurnstileInContainer(turnstileContainer);

        if (ok && data.success && data.client_id && data.client_secret) {
            form.reset(); // 成功后重置表单
            if (newClientIdDisplay) newClientIdDisplay.textContent = data.client_id;
            if (newClientSecretDisplay) newClientSecretDisplay.textContent = data.client_secret;
            if (newOauthClientCredentialsDiv) newOauthClientCredentialsDiv.classList.remove('hidden'); // 显示新凭据
            if (typeof showMessage === 'function') showMessage('应用注册成功！请妥善保管您的客户端密钥，它仅显示这一次。', 'success');
            loadRegisteredOauthClients(); // 重新加载应用列表 (此函数不应再隐藏新凭据)
        } else {
            if (typeof showMessage === 'function') showMessage(data.error || `应用注册失败 (${status})`, 'error');
        }
    }
}

/**
 * 加载并显示用户已注册的 OAuth 客户端应用列表。
 */
async function loadRegisteredOauthClients() {
    registeredOauthClientsListDiv = registeredOauthClientsListDiv || document.getElementById('registered-oauth-clients-list');
    if (!registeredOauthClientsListDiv) return;

    registeredOauthClientsListDiv.innerHTML = '<p>正在加载应用列表...</p>';
    // 此函数不应负责隐藏 newOauthClientCredentialsDiv，该操作由 activateTab 或 handleRegisterOauthClientSubmit 初始化时处理。

    if (typeof apiCall === 'function') {
        const { ok, data, status } = await apiCall('/api/oauth/clients'); // GET request
        if (ok && data.success && Array.isArray(data.clients)) {
            if (data.clients.length === 0) {
                registeredOauthClientsListDiv.innerHTML = '<p>您还没有注册任何 OAuth 应用。</p>';
                return;
            }
            let html = '';
            data.clients.forEach(client => {
                let displayRedirectUri = '未设置';
                try {
                    // redirect_uris 在数据库中存储为 JSON 字符串数组
                    const uris = JSON.parse(client.redirect_uris || '[]');
                    if (uris.length > 0) displayRedirectUri = window.escapeHtml(uris[0]); // 通常只显示第一个
                } catch (e) {
                    console.error("Error parsing redirect_uris for client " + client.client_id, client.redirect_uris, e);
                }

                html += `
                    <div class="application-card">
                        <h4>${window.escapeHtml(client.client_name)}</h4>
                        <p><strong>客户端 ID:</strong> <code>${window.escapeHtml(client.client_id)}</code> 
                           <button type="button" class="button small secondary" style="padding: 3px 8px; font-size:0.8em; margin-left:5px;" onclick="copyToClipboard('${window.escapeHtml(client.client_id)}', '客户端 ID')">复制</button>
                        </p>
                        <p><strong>回调地址:</strong> <code>${displayRedirectUri}</code></p>
                        <p><strong>应用主页:</strong> ${client.client_website ? `<a href="${window.escapeHtml(client.client_website)}" target="_blank" rel="noopener noreferrer" class="external-paste-link">${window.escapeHtml(client.client_website)}</a>` : '未设置'}</p>
                        <p><strong>描述:</strong> ${client.client_description ? window.escapeHtml(client.client_description) : '无'}</p>
                        <p><strong>创建日期:</strong> ${new Date(client.created_at * 1000).toLocaleDateString()}</p>
                        </div>
                `;
            });
            registeredOauthClientsListDiv.innerHTML = html;
        } else {
            registeredOauthClientsListDiv.innerHTML = `<p style="color: var(--danger-color);">加载应用列表失败: ${data.error || '状态码 ' + status}</p>`;
        }
    }
}

// DOMContentLoaded 后绑定事件
document.addEventListener('DOMContentLoaded', () => {
    // 获取 DOM 元素
    registerOauthClientForm = document.getElementById('register-oauth-client-form');
    newOauthClientCredentialsDiv = document.getElementById('new-oauth-client-credentials');
    newClientIdDisplay = document.getElementById('new-client-id-display');
    newClientSecretDisplay = document.getElementById('new-client-secret-display');
    registeredOauthClientsListDiv = document.getElementById('registered-oauth-clients-list');

    // 绑定事件监听器
    if (registerOauthClientForm) {
        registerOauthClientForm.addEventListener('submit', handleRegisterOauthClientSubmit);
    }

    // 将需要在 activateTab 中调用的函数挂载到 window
    window.loadOauthAppsTabData = loadOauthAppsTabData;

    // TODO: 实现 editOauthClient 和 deleteOauthClient 函数，并绑定事件（如果添加了编辑/删除按钮）
    // window.editOauthClient = async function(clientId) { /* ... */ }
    // window.deleteOauthClient = async function(clientId) { /* ... */ }
});
