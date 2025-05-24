let registerOauthClientForm, newOauthClientCredentialsDiv, newClientIdDisplay, newClientSecretDisplay;
let registeredOauthClientsListDiv;

function loadOauthAppsTabData() {
    loadRegisteredOauthClients();
    const oauthClientTurnstile = document.querySelector('#register-oauth-client-form .cf-turnstile');
    if (oauthClientTurnstile && oauthClientTurnstile.offsetParent !== null) { 
        if (typeof renderTurnstile === 'function') renderTurnstile(oauthClientTurnstile);
    }
}

async function handleRegisterOauthClientSubmit(event) {
    event.preventDefault();
    if (typeof clearMessages === 'function') clearMessages();
    if (newOauthClientCredentialsDiv) newOauthClientCredentialsDiv.classList.add('hidden'); 

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
            form.reset(); 
            if (newClientIdDisplay) newClientIdDisplay.textContent = data.client_id;
            if (newClientSecretDisplay) newClientSecretDisplay.textContent = data.client_secret;
            if (newOauthClientCredentialsDiv) newOauthClientCredentialsDiv.classList.remove('hidden'); 
            if (typeof showMessage === 'function') showMessage('应用注册成功！请妥善保管您的客户端密钥，它仅显示这一次。', 'success');
            loadRegisteredOauthClients(); 
        } else {
            if (typeof showMessage === 'function') showMessage(data.error || `应用注册失败 (${status})`, 'error');
        }
    }
}

async function loadRegisteredOauthClients() {
    registeredOauthClientsListDiv = registeredOauthClientsListDiv || document.getElementById('registered-oauth-clients-list');
    if (!registeredOauthClientsListDiv) return;

    registeredOauthClientsListDiv.innerHTML = '<p>正在加载应用列表...</p>';

    if (typeof apiCall === 'function') {
        const { ok, data, status } = await apiCall('/api/oauth/clients'); 
        if (ok && data.success && Array.isArray(data.clients)) {
            if (data.clients.length === 0) {
                registeredOauthClientsListDiv.innerHTML = '<p>您还没有注册任何 OAuth 应用。</p>';
                return;
            }
            let html = '';
            data.clients.forEach(client => {
                let displayRedirectUri = '未设置';
                try {
                    const uris = JSON.parse(client.redirect_uris || '[]');
                    if (uris.length > 0) displayRedirectUri = window.escapeHtml(uris[0]); 
                } catch (e) {
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

document.addEventListener('DOMContentLoaded', () => {
    registerOauthClientForm = document.getElementById('register-oauth-client-form');
    newOauthClientCredentialsDiv = document.getElementById('new-oauth-client-credentials');
    newClientIdDisplay = document.getElementById('new-client-id-display');
    newClientSecretDisplay = document.getElementById('new-client-secret-display');
    registeredOauthClientsListDiv = document.getElementById('registered-oauth-clients-list');

    if (registerOauthClientForm) {
        registerOauthClientForm.addEventListener('submit', handleRegisterOauthClientSubmit);
    }

    window.loadOauthAppsTabData = loadOauthAppsTabData;
});
