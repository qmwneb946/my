// 前端主脚本 - 核心逻辑
// Frontend Main Script - Core Logic

// 全局/模块作用域变量
let TURNSTILE_SITE_KEY = '0x4AAAAAABHKV0NoiFCSQFUk'; // 默认测试密钥，会被 /api/config 的值覆盖
const activeTurnstileWidgets = new Map();
let loginEmailFor2FA = null;
// currentActiveConversationId 和 currentUserEmail 由 ui-messaging.js 管理

// DOM 元素引用 (在 DOMContentLoaded 中初始化)
let messageArea, authSection, loggedInSection, loginFormEl, registerFormEl;
let topBarUserEmail, topBarUserUsername, topBarUserInfo, topBarAuthButtons, topBarLogoutButton;
let accountTabs = [], tabPanes = [];
let themeToggleButton, themeToggleDarkIcon, themeToggleLightIcon;
let unreadMessagesIndicator; 

// --- Turnstile 相关函数 ---
function renderTurnstile(containerElement) {
    if (!containerElement || !window.turnstile || typeof window.turnstile.render !== 'function') {
        return;
    }
    if (!TURNSTILE_SITE_KEY) {
        console.error("Turnstile Site Key is not available. Cannot render widget.");
        return;
    }
    if (activeTurnstileWidgets.has(containerElement)) {
        const oldWidgetId = activeTurnstileWidgets.get(containerElement);
        try { turnstile.remove(oldWidgetId); } catch (e) { console.warn("Error removing old Turnstile widget:", oldWidgetId, e); }
        activeTurnstileWidgets.delete(containerElement);
    }
    containerElement.innerHTML = '';
    try {
        const widgetId = turnstile.render(containerElement, {
            sitekey: TURNSTILE_SITE_KEY,
            callback: (token) => {
                const specificCallbackName = containerElement.getAttribute('data-callback');
                if (specificCallbackName && typeof window[specificCallbackName] === 'function') {
                    window[specificCallbackName](token);
                }
            }
        });
        if (widgetId) activeTurnstileWidgets.set(containerElement, widgetId);
        else console.warn("Turnstile render did not return a widgetId for container:", containerElement);
    } catch (e) { console.error("Error rendering Turnstile widget in container:", containerElement, e); }
}

function removeTurnstile(containerElement) {
    if (containerElement && activeTurnstileWidgets.has(containerElement)) {
        const widgetId = activeTurnstileWidgets.get(containerElement);
        if (window.turnstile && typeof window.turnstile.remove === 'function') {
            try { turnstile.remove(widgetId); } catch (e) { console.warn("Error removing Turnstile widget:", widgetId, e); }
        }
        activeTurnstileWidgets.delete(containerElement);
    }
}

function resetTurnstileInContainer(containerElement) {
    if (containerElement && activeTurnstileWidgets.has(containerElement)) {
        const widgetId = activeTurnstileWidgets.get(containerElement);
        if (window.turnstile && typeof window.turnstile.reset === 'function') {
            try { turnstile.reset(widgetId); } catch (e) { console.error("Error resetting Turnstile widget:", widgetId, e); }
        }
    } else if (containerElement) {
        renderTurnstile(containerElement);
    }
}

// --- 消息和 API 调用辅助函数 ---
function clearMessages() { if (messageArea) { messageArea.textContent = ''; messageArea.className = 'message hidden'; } }

function showMessage(text, type = 'error', isHtml = false) {
    if (messageArea) {
        if (isHtml) { messageArea.innerHTML = text; } else { messageArea.textContent = text; }
        messageArea.className = 'message ' + type; messageArea.classList.remove('hidden');
        window.scrollTo(0, 0);
    }
}

async function apiCall(endpoint, method = 'GET', body = null) {
    const options = { method, headers: {}, credentials: 'include' };
    if (body) { options.headers['Content-Type'] = 'application/json'; options.body = JSON.stringify(body); }
    try {
        const response = await fetch(endpoint, options);
        let resultData = {};
        const contentType = response.headers.get("content-type");
        if (contentType && contentType.includes("application/json") && response.status !== 204) {
             try {
                resultData = await response.json();
            } catch (e) {
                if (response.ok) console.warn(`API call to ${endpoint} returned non-JSON with status ${response.status}`);
                else throw e;
            }
        }
        return { ok: response.ok, status: response.status, data: resultData };
    } catch (e) {
        console.error('API Call Error:', { endpoint, error: e });
        showMessage('发生网络或服务器错误，请稍后重试或联系管理员。', 'error');
        return { ok: false, status: 0, data: { error: '网络或解析错误，请检查控制台。' } };
    }
}

// --- 核心 UI 逻辑 ---
function applyTheme(isDark) {
    document.body.classList.toggle('dark-mode', isDark);
    if (themeToggleDarkIcon) themeToggleDarkIcon.classList.toggle('hidden', !isDark);
    if (themeToggleLightIcon) themeToggleLightIcon.classList.toggle('hidden', isDark);

    const qrCodeDisplay = document.getElementById('qrcode-display');
    const otpAuthUriTextDisplay = document.getElementById('otpauth-uri-text-display');
    if (qrCodeDisplay && qrCodeDisplay.innerHTML !== '' && typeof QRCode !== 'undefined' && otpAuthUriTextDisplay) {
        const otpauthUri = otpAuthUriTextDisplay.textContent;
        if (otpauthUri) {
            qrCodeDisplay.innerHTML = '';
            new QRCode(qrCodeDisplay, {
                text: otpauthUri,
                width: 180, height: 180,
                colorDark: isDark ? "#e2e8f0" : "#000000",
                colorLight: isDark ? "#2d3748" : "#ffffff",
                correctLevel: QRCode.CorrectLevel.H
            });
        }
    }
}

function activateTab(tabToActivate) {
    if (!tabToActivate || !tabPanes || !accountTabs) return;
    const paneIdToActivate = tabToActivate.dataset.paneId;

    tabPanes.forEach(pane => {
        const turnstileDivsInPane = pane.querySelectorAll('.cf-turnstile');
        if (pane.id === paneIdToActivate) {
            pane.classList.remove('hidden');
            turnstileDivsInPane.forEach(div => renderTurnstile(div));
            if (pane.id === 'tab-content-api-keys' && typeof window.loadApiKeysTabData === 'function') window.loadApiKeysTabData();
            if (pane.id === 'tab-content-my-applications' && typeof window.loadOauthAppsTabData === 'function') window.loadOauthAppsTabData();
            if (pane.id === 'tab-content-messaging' && typeof window.loadMessagingTabData === 'function') window.loadMessagingTabData();
        } else {
            turnstileDivsInPane.forEach(div => removeTurnstile(div));
            pane.classList.add('hidden');
        }
    });
    accountTabs.forEach(tab => tab.classList.remove('selected'));
    tabToActivate.classList.add('selected');
    clearMessages();

    const newlyCreatedApiKeyDisplayDiv = document.getElementById('newly-created-api-key-display');
    const newOauthClientCredentialsDiv = document.getElementById('new-oauth-client-credentials');
    if (newlyCreatedApiKeyDisplayDiv) newlyCreatedApiKeyDisplayDiv.classList.add('hidden');
    if (newOauthClientCredentialsDiv) newOauthClientCredentialsDiv.classList.add('hidden');
}

function displayCorrectView(userData) {
    clearMessages();
    const isLoggedIn = !!userData?.email;
    document.querySelectorAll('.cf-turnstile').forEach(div => removeTurnstile(div));

    if (topBarUserInfo) topBarUserInfo.classList.toggle('hidden', !isLoggedIn);
    if (isLoggedIn && topBarUserEmail) topBarUserEmail.textContent = userData.email || '未知邮箱';
    if (isLoggedIn && topBarUserUsername) topBarUserUsername.textContent = userData.username || '用户';
    if (topBarAuthButtons) topBarAuthButtons.classList.toggle('hidden', isLoggedIn);
    if (topBarLogoutButton) topBarLogoutButton.classList.toggle('hidden', !isLoggedIn);

    const currentPath = window.location.pathname;
    if (isLoggedIn) {
        if (['/', '/user/login', '/user/register'].includes(currentPath)) { window.location.pathname = '/user/account'; return; }
        if(authSection) authSection.classList.add('hidden');
        if(loggedInSection) loggedInSection.classList.remove('hidden');

        if (typeof window.initializePersonalInfoForm === 'function') window.initializePersonalInfoForm(userData);
        if (typeof window.initializeSecuritySettings === 'function') window.initializeSecuritySettings(userData);
        if (typeof window.updateUnreadMessagesIndicator === 'function') window.updateUnreadMessagesIndicator();

        const defaultTabId = 'tab-personal-info'; 
        let tabToActivateId = defaultTabId;
        if (window.location.hash) {
            const hashTabId = window.location.hash.substring(1); 
            if (document.getElementById(hashTabId) && document.getElementById(hashTabId).classList.contains('tab-entry')) {
                tabToActivateId = hashTabId;
            }
        }
        const tabToActivate = document.getElementById(tabToActivateId) || document.getElementById(defaultTabId);
        if (tabToActivate) activateTab(tabToActivate);

    } else { 
        if (currentPath === '/user/account') { window.location.pathname = '/user/login'; return; }
        if(loggedInSection) loggedInSection.classList.add('hidden');
        if(authSection) authSection.classList.remove('hidden');
        const login2FASection = document.getElementById('login-2fa-section');

        if (currentPath === '/' || currentPath === '/user/login') {
            if(loginFormEl) { loginFormEl.classList.remove('hidden'); loginFormEl.querySelector('form')?.reset(); renderTurnstile(loginFormEl.querySelector('.cf-turnstile')); }
            if(registerFormEl) registerFormEl.classList.add('hidden');
        } else if (currentPath === '/user/register') {
            if(loginFormEl) loginFormEl.classList.add('hidden');
            if(registerFormEl) { registerFormEl.classList.remove('hidden'); registerFormEl.querySelector('form')?.reset(); renderTurnstile(registerFormEl.querySelector('.cf-turnstile'));}
        }
        if(login2FASection) login2FASection.classList.add('hidden');
        loginEmailFor2FA = null;
    }
}

async function fetchAppConfigAndInitialize() {
    try {
        const response = await fetch('/api/config');
        if (response.ok) {
            const config = await response.json();
            if (config.turnstileSiteKey) {
                TURNSTILE_SITE_KEY = config.turnstileSiteKey;
            } else {
                console.warn("Turnstile Site Key not provided by /api/config, using default test key.");
            }
        } else {
            console.error("Failed to fetch app config from /api/config, status:", response.status);
        }
    } catch (error) {
        console.error("Error fetching app config:", error);
    }
    await checkLoginStatus();
}


async function checkLoginStatus() {
    const { ok, status, data } = await apiCall('/api/me');
    displayCorrectView(ok && data.email ? data : null);

    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.has('registered') && (window.location.pathname === '/user/login' || window.location.pathname === '/')) {
        showMessage('注册成功！请使用您的邮箱或用户名登录。', 'success');
        const newUrl = new URL(window.location);
        newUrl.searchParams.delete('registered');
        window.history.replaceState({}, document.title, newUrl.toString());
    }
}

// --- 辅助函数，之前可能在 helpers.js 但这里也需要 ---
function isValidEmail(email) {
    if (typeof email !== 'string') return false;
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}


// --- DOMContentLoaded 事件监听 ---
document.addEventListener('DOMContentLoaded', () => {
    messageArea = document.getElementById('message-area');
    authSection = document.getElementById('auth-section');
    loggedInSection = document.getElementById('logged-in-section');
    loginFormEl = document.getElementById('login-form-el'); 
    registerFormEl = document.getElementById('register-form-el'); 

    topBarUserEmail = document.getElementById('top-bar-user-email');
    topBarUserUsername = document.getElementById('top-bar-user-username');
    topBarUserInfo = document.getElementById('top-bar-user-info');
    topBarAuthButtons = document.getElementById('top-bar-auth-buttons');
    topBarLogoutButton = document.getElementById('top-bar-logout-button');
    unreadMessagesIndicator = document.getElementById('unread-messages-indicator');

    accountTabs = Array.from(document.querySelectorAll('#account-tabs .tab-entry'));
    tabPanes = Array.from(document.querySelectorAll('.tab-pane'));

    themeToggleButton = document.getElementById('theme-toggle-button');
    themeToggleDarkIcon = document.getElementById('theme-toggle-dark-icon');
    themeToggleLightIcon = document.getElementById('theme-toggle-light-icon');

    let isDarkMode = localStorage.getItem('theme') === 'dark' || (localStorage.getItem('theme') === null && window.matchMedia('(prefers-color-scheme: dark)').matches);
    applyTheme(isDarkMode);
    if (themeToggleButton) themeToggleButton.addEventListener('click', () => { isDarkMode = !isDarkMode; localStorage.setItem('theme', isDarkMode ? 'dark' : 'light'); applyTheme(isDarkMode); });
    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', e => { if (localStorage.getItem('theme') === null) { isDarkMode = e.matches; applyTheme(isDarkMode); } });

    accountTabs.forEach(tab => {
        tab.addEventListener('click', (event) => {
            activateTab(event.target);
            if (event.target.id) {
                window.location.hash = event.target.id;
            }
        });
    });

    if (loginFormEl) loginFormEl.addEventListener('submit', (event) => handleAuth(event, 'login'));
    if (registerFormEl) registerFormEl.addEventListener('submit', (event) => handleAuth(event, 'register'));
    if (topBarLogoutButton) topBarLogoutButton.addEventListener('click', handleLogout);

    fetchAppConfigAndInitialize();
});

// --- 全局可访问的事件处理和辅助函数 ---
window.handleAuth = async function(event, type) {
    event.preventDefault(); clearMessages();
    const form = event.target;
    const turnstileContainer = form.querySelector('.cf-turnstile');
    const turnstileToken = form.querySelector('[name="cf-turnstile-response"]')?.value;
    const login2FASection = document.getElementById('login-2fa-section');
    const loginTotpCodeInput = document.getElementById('login-totp-code');

    if (!turnstileToken && turnstileContainer) {
        showMessage('人机验证失败，请刷新页面或稍后重试。', 'error');
        if (turnstileContainer) resetTurnstileInContainer(turnstileContainer);
        return;
    }
    let endpoint = '', requestBody = {};
    if (type === 'login') {
        const identifier = form.elements['identifier'].value, password = form.elements['password'].value;
        const totpCode = loginTotpCodeInput ? loginTotpCodeInput.value : '';
        if (!identifier || !password) { showMessage('邮箱/用户名和密码不能为空。'); return; }
        if (loginEmailFor2FA && totpCode) { endpoint = '/api/login/2fa-verify'; requestBody = { email: loginEmailFor2FA, totpCode }; }
        else { endpoint = '/api/login'; requestBody = { identifier, password, turnstileToken }; }
    } else { // register
        endpoint = '/api/register';
        const {email, username, password, confirmPassword, phoneNumber} = Object.fromEntries(new FormData(form));
        if (password !== confirmPassword) { showMessage('两次输入的密码不一致。'); return; }
        if (!email || !username || !password) { showMessage('邮箱、用户名和密码为必填项。'); return; }
        if (password.length < 6) { showMessage('密码至少需要6个字符。'); return; }
        requestBody = { email, username, password, confirmPassword, phoneNumber, turnstileToken };
    }
    const { ok, status, data } = await apiCall(endpoint, 'POST', requestBody);
    if (turnstileContainer) resetTurnstileInContainer(turnstileContainer);
    if (ok && data.success) {
        if (data.twoFactorRequired && data.email) {
            showMessage('需要两步验证。请输入验证码。', 'info'); loginEmailFor2FA = data.email;
            if(login2FASection) login2FASection.classList.remove('hidden'); if(loginTotpCodeInput) loginTotpCodeInput.focus();
        } else {
            form.reset();
            if(login2FASection) login2FASection.classList.add('hidden'); loginEmailFor2FA = null;
            if (type === 'login' || (type === 'login' && loginEmailFor2FA) || (data.twoFactorRequired === undefined)) window.location.pathname = '/user/account';
            else window.location.href = '/user/login?registered=true';
        }
    } else {
        showMessage(data.error || ('操作失败 (' + status + ')'), 'error', data.details ? true : false);
        if (data.details) console.error("Turnstile error codes:", data.details);
        if (type === 'login' && loginEmailFor2FA && status !== 401 && login2FASection) { login2FASection.classList.remove('hidden'); }
        else if (status === 401 && data.error === '两步验证码无效' && login2FASection) {
            login2FASection.classList.remove('hidden'); if(loginTotpCodeInput) { loginTotpCodeInput.value = ''; loginTotpCodeInput.focus(); }
        } else if (login2FASection) { login2FASection.classList.add('hidden'); loginEmailFor2FA = null; }
    }
};

window.handleLogout = async function() {
    clearMessages();
    await apiCall('/api/logout', 'POST');
    window.location.pathname = '/user/login';
};

window.turnstileCallbackLogin = function(token) { /* console.log('Login Turnstile token:', token); */ };
window.turnstileCallbackRegister = function(token) { /* console.log('Register Turnstile token:', token); */ };
window.turnstileCallbackPasteApi = function(token) { /* console.log('Paste API Turnstile token:', token); */ };
window.turnstileCallbackCloudPc = function(token) { /* console.log('Cloud PC Turnstile token:', token); */ };
window.turnstileCallbackOauthClient = function(token) { /* console.log('OAuth Client Reg Turnstile token:', token); */ };

window.copyToClipboard = function(text, itemNameToCopy = '内容') {
    if (!text) { showMessage('没有可复制的'+itemNameToCopy+'。', 'warning'); return; }
    navigator.clipboard.writeText(text).then(() => {
         showMessage(itemNameToCopy + '已复制到剪贴板！', 'success');
    }).catch(err => {
        showMessage('复制失败: ' + err, 'error');
        console.error('Failed to copy ' + itemNameToCopy + ':', err);
    });
};

window.escapeHtml = function(unsafe) {
    if (unsafe === null || typeof unsafe === 'undefined') return '';
    return String(unsafe)
         .replace(/&/g, "&amp;")
         .replace(/</g, "&lt;")
         .replace(/>/g, "&gt;")
         .replace(/"/g, "&quot;")
         .replace(/'/g, "&#039;");
};

// 将其他模块可能需要调用的核心函数暴露到 window
window.apiCall = apiCall;
window.showMessage = showMessage;
window.clearMessages = clearMessages;
window.renderTurnstile = renderTurnstile;
window.removeTurnstile = removeTurnstile;
window.resetTurnstileInContainer = resetTurnstileInContainer;
window.checkLoginStatus = checkLoginStatus;
window.isValidEmail = isValidEmail; // *** 新增：将 isValidEmail 暴露到全局 ***
