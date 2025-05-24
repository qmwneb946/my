let TURNSTILE_SITE_KEY = '1x00000000000000000000AA';
const activeTurnstileWidgets = new Map();
let loginEmailFor2FA = null;
let currentUserData = null;
let messageArea, authSection, loggedInSection, loginFormEl, registerFormEl, adminSection;
let topBarUserEmailEl, topBarUserUsernameEl, topBarUserInfoEl, topBarAuthButtonsEl, topBarLogoutButtonEl, userMenuButtonEl, userDropdownMenuEl, topBarAccountLinkEl, topBarAdminLinkEl;
let sidebarEl, sidebarToggleEl, mainContentContainerEl, sidebarOverlayEl;
let accountTabLinks = [], adminTabLinks = [];
let tabPanes = [];
let themeToggleButton, themeToggleDarkIcon, themeToggleLightIcon;
let unreadMessagesIndicator;
let appWrapper;
let topBarMessagingButton;
let userPresenceSocket = null;
const pathToPaneIdMap = {
    '/user/profile': 'tab-content-personal-info',
    '/user/security': 'tab-content-security-settings',
    '/user/api-keys': 'tab-content-api-keys',
    '/user/applications': 'tab-content-my-applications',
    '/user/messaging': 'tab-content-messaging',
    '/user/admin': 'tab-content-admin-users',
    '/user/admin/users': 'tab-content-admin-users',
    '/user/admin/apps': 'tab-content-admin-apps'
};
function renderTurnstile(containerElement) {
    if (!containerElement || !window.turnstile || typeof window.turnstile.render !== 'function') return;
    if (!TURNSTILE_SITE_KEY) { return; }
    if (activeTurnstileWidgets.has(containerElement)) {
        try { turnstile.remove(activeTurnstileWidgets.get(containerElement)); } catch (e) { }
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
    } catch (e) { }
}
function removeTurnstile(containerElement) {
    if (containerElement && activeTurnstileWidgets.has(containerElement)) {
        try { turnstile.remove(activeTurnstileWidgets.get(containerElement)); } catch (e) { }
        activeTurnstileWidgets.delete(containerElement);
    }
}
function resetTurnstileInContainer(containerElement) {
    if (containerElement && activeTurnstileWidgets.has(containerElement)) {
        try { turnstile.reset(activeTurnstileWidgets.get(containerElement)); } catch (e) { }
    } else if (containerElement) {
        renderTurnstile(containerElement);
    }
}
function clearMessages() { if (messageArea) { messageArea.textContent = ''; messageArea.className = 'message hidden'; } }
function showMessage(text, type = 'error', isHtml = false) {
    if (messageArea) {
        if (isHtml) { messageArea.innerHTML = text; } else { messageArea.textContent = text; }
        messageArea.className = 'message ' + type; messageArea.classList.remove('hidden');
        const mainContent = document.getElementById('main-content');
        if (mainContent) {
            mainContent.scrollTo({ top: 0, behavior: 'smooth' });
        } else {
            window.scrollTo({ top: 0, behavior: 'smooth' });
        }
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
             try { resultData = await response.json(); } catch (e) { }
        }
        return { ok: response.ok, status: response.status, data: resultData };
    } catch (e) {
        showMessage('发生网络或服务器错误，请稍后重试。', 'error');
        return { ok: false, status: 0, data: { error: '网络错误' } };
    }
}
function updateUnreadMessagesIndicatorUI(count) {
    const localUnreadIndicator = document.getElementById('unread-messages-indicator');
    const localMessagingButton = document.getElementById('top-bar-messaging-button');
    if (!localUnreadIndicator || !localMessagingButton) return;
    if (count > 0) {
        localUnreadIndicator.textContent = count;
        localUnreadIndicator.classList.remove('hidden');
        localMessagingButton.classList.add('active');
    } else {
        localUnreadIndicator.textContent = '';
        localUnreadIndicator.classList.add('hidden');
        localMessagingButton.classList.remove('active');
    }
}
function connectUserPresenceWebSocket() {
    if (userPresenceSocket && (userPresenceSocket.readyState === WebSocket.OPEN || userPresenceSocket.readyState === WebSocket.CONNECTING)) {
        return;
    }
    if (!currentUserData || !currentUserData.email) {
        return;
    }
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/api/ws/user`;
    userPresenceSocket = new WebSocket(wsUrl);
    userPresenceSocket.onopen = () => {
    };
    userPresenceSocket.onmessage = (event) => {
        try {
            const message = JSON.parse(event.data);
            if (message.type === "CONVERSATIONS_LIST") {
                if (typeof window.handleConversationsListUpdate === 'function') {
                    window.handleConversationsListUpdate(message.data);
                }
            } else if (message.type === "UNREAD_COUNT_TOTAL") {
                updateUnreadMessagesIndicatorUI(message.data.unread_count);
            } else if (message.type === "CONVERSATION_UPDATE") {
                 if (typeof window.handleSingleConversationUpdate === 'function') {
                    window.handleSingleConversationUpdate(message.data);
                }
            }
        } catch (e) {
        }
    };
    userPresenceSocket.onclose = (event) => {
        userPresenceSocket = null;
        if (currentUserData && currentUserData.email) {
            setTimeout(connectUserPresenceWebSocket, 5000);
        }
    };
    userPresenceSocket.onerror = (error) => {
    };
}
function applyTheme(isDark) {
    document.body.classList.toggle('dark-mode', isDark);
    if (themeToggleDarkIcon) themeToggleDarkIcon.style.display = isDark ? 'block' : 'none';
    if (themeToggleLightIcon) themeToggleLightIcon.style.display = isDark ? 'none' : 'block';
    const qrCodeDisplay = document.getElementById('qrcode-display');
    const otpAuthUriTextDisplay = document.getElementById('otpauth-uri-text-display');
    if (qrCodeDisplay && typeof QRCode !== 'undefined' && otpAuthUriTextDisplay) {
        const otpauthUri = otpAuthUriTextDisplay.textContent;
        if (otpauthUri && qrCodeDisplay.innerHTML.includes('canvas')) {
            qrCodeDisplay.innerHTML = '';
            new QRCode(qrCodeDisplay, {
                text: otpauthUri, width: 180, height: 180,
                colorDark: isDark ? "#e2e8f0" : "#000000",
                colorLight: "#ffffff",
                correctLevel: QRCode.CorrectLevel.H
            });
        }
    }
}
function toggleSidebar() {
    if (sidebarEl && sidebarOverlayEl && appWrapper) {
        const isOpen = sidebarEl.classList.toggle('open');
        sidebarOverlayEl.classList.toggle('hidden', !isOpen);
        appWrapper.classList.toggle('sidebar-open-app', isOpen);
    }
}
function activatePane(paneIdToActivate) {
    if (!paneIdToActivate) return;
    const allNavLinks = [...accountTabLinks, ...adminTabLinks];
    allNavLinks.forEach(link => {
        link.classList.toggle('selected', link.dataset.paneId === paneIdToActivate);
    });
    if (topBarMessagingButton) {
        topBarMessagingButton.classList.toggle('active', paneIdToActivate === 'tab-content-messaging');
    }
    if (!mainContentContainerEl) return;
    tabPanes.forEach(pane => {
        const turnstileDivsInPane = pane.querySelectorAll('.cf-turnstile');
        if (pane.id === paneIdToActivate) {
            pane.classList.remove('hidden');
            turnstileDivsInPane.forEach(div => renderTurnstile(div));
            mainContentContainerEl.classList.toggle('messaging-active', pane.id === 'tab-content-messaging');
            if (pane.id === 'tab-content-api-keys' && typeof window.initializeApiKeysTab === 'function') window.initializeApiKeysTab();
            if (pane.id === 'tab-content-my-applications' && typeof window.loadOauthAppsTabData === 'function') window.loadOauthAppsTabData();
            if (pane.id === 'tab-content-messaging' && typeof window.loadMessagingTabData === 'function') window.loadMessagingTabData();
            if (pane.id === 'tab-content-security-settings' && typeof window.initializeSecuritySettings === 'function') {
                if (currentUserData) {
                    window.initializeSecuritySettings(currentUserData);
                } else {
                    apiCall('/api/me').then(response => {
                        if (response.ok && response.data) {
                            currentUserData = response.data;
                            window.initializeSecuritySettings(currentUserData);
                        }
                    });
                }
            }
            if (pane.id === 'tab-content-admin-users' && typeof window.loadAdminUsersData === 'function') window.loadAdminUsersData();
            if (pane.id === 'tab-content-admin-apps' && typeof window.loadAdminOauthClientsData === 'function') window.loadAdminOauthClientsData();
        } else {
            turnstileDivsInPane.forEach(div => removeTurnstile(div));
            pane.classList.add('hidden');
        }
    });
    clearMessages();
    const newlyCreatedApiKeyDisplayDiv = document.getElementById('newly-created-api-key-display');
    const newOauthClientCredentialsDiv = document.getElementById('new-oauth-client-credentials');
    if (newlyCreatedApiKeyDisplayDiv) newlyCreatedApiKeyDisplayDiv.classList.add('hidden');
    if (newOauthClientCredentialsDiv) newOauthClientCredentialsDiv.classList.add('hidden');
    if (window.innerWidth < 769 && sidebarEl && sidebarEl.classList.contains('open')) {
        toggleSidebar();
    }
    if (paneIdToActivate === 'tab-content-messaging') {
        if (typeof window.updateUnreadMessagesIndicator === 'function') {
             window.updateUnreadMessagesIndicator();
        } else if (userPresenceSocket && userPresenceSocket.readyState === WebSocket.OPEN) {
            userPresenceSocket.send(JSON.stringify({type: "REQUEST_INITIAL_STATE"}));
        }
    }
}
function displayCorrectView(userData) {
    clearMessages();
    currentUserData = userData;
    const isLoggedIn = !!userData?.email;
    const isAdmin = isLoggedIn && userData.is_admin === true;
    document.querySelectorAll('.cf-turnstile').forEach(div => removeTurnstile(div));
    if (topBarUserInfoEl) topBarUserInfoEl.classList.toggle('hidden', !isLoggedIn);
    if (isLoggedIn && topBarUserEmailEl) topBarUserEmailEl.textContent = userData.email || '未知邮箱';
    if (isLoggedIn && topBarUserUsernameEl) topBarUserUsernameEl.textContent = userData.username || '用户';
    if (topBarAuthButtonsEl) topBarAuthButtonsEl.classList.toggle('hidden', isLoggedIn);
    if (topBarMessagingButton) topBarMessagingButton.classList.toggle('hidden', !isLoggedIn);
    if (topBarAdminLinkEl) topBarAdminLinkEl.classList.toggle('hidden', !isAdmin);
    const adminTabsUl = document.getElementById('admin-tabs');
    if (adminTabsUl) adminTabsUl.classList.toggle('hidden', !isAdmin);
    const currentPath = window.location.pathname;
    if (isLoggedIn) {
        if (sidebarEl) sidebarEl.classList.remove('hidden');
        if (appWrapper) appWrapper.classList.add('logged-in-layout');
        if (appWrapper) appWrapper.classList.remove('logged-out-layout');
        if (['/', '/user/login', '/user/register'].includes(currentPath)) {
            window.location.pathname = isAdmin ? '/user/admin/users' : '/user/profile';
            return;
        }
        if(authSection) authSection.classList.add('hidden');
        if(loggedInSection) loggedInSection.classList.toggle('hidden', currentPath.startsWith('/user/admin'));
        if(adminSection) adminSection.classList.toggle('hidden', !currentPath.startsWith('/user/admin'));
        if (typeof window.initializePersonalInfoForm === 'function') window.initializePersonalInfoForm(userData);
        connectUserPresenceWebSocket();
        let paneIdToActivate = pathToPaneIdMap[currentPath];
        if (!paneIdToActivate) {
            paneIdToActivate = isAdmin ? 'tab-content-admin-users' : 'tab-content-personal-info';
        }
        if (!isAdmin && paneIdToActivate.startsWith('tab-content-admin-')) {
             window.location.pathname = '/user/profile'; return;
        }
        activatePane(paneIdToActivate);
        const allNavLinks = [...accountTabLinks, ...adminTabLinks];
        allNavLinks.forEach(link => {
            link.classList.toggle('selected', link.dataset.paneId === paneIdToActivate);
        });
    } else {
        if (userPresenceSocket && userPresenceSocket.readyState === WebSocket.OPEN) {
            userPresenceSocket.close();
            userPresenceSocket = null;
        }
        if (sidebarEl) sidebarEl.classList.add('hidden');
        if (appWrapper) appWrapper.classList.remove('logged-in-layout');
        if (appWrapper) appWrapper.classList.add('logged-out-layout');
        if (mainContentContainerEl) mainContentContainerEl.classList.remove('messaging-active');
        if (Object.keys(pathToPaneIdMap).includes(currentPath) || currentPath === '/user/account' || currentPath.startsWith('/user/admin')) {
            window.location.pathname = '/user/login'; return;
        }
        if(loggedInSection) loggedInSection.classList.add('hidden');
        if(adminSection) adminSection.classList.add('hidden');
        if(authSection) authSection.classList.remove('hidden');
        const login2FASection = document.getElementById('login-2fa-section');
        const loginFormContainer = document.getElementById('login-form');
        const registerFormContainer = document.getElementById('register-form');
        if (currentPath === '/' || currentPath === '/user/login') {
            if(loginFormContainer) { loginFormContainer.classList.remove('hidden'); if(loginFormEl) loginFormEl.reset(); renderTurnstile(loginFormContainer.querySelector('.cf-turnstile')); }
            if(registerFormContainer) registerFormContainer.classList.add('hidden');
        } else if (currentPath === '/user/register') {
            if(loginFormContainer) loginFormContainer.classList.add('hidden');
            if(registerFormContainer) { registerFormContainer.classList.remove('hidden'); if(registerFormEl) registerFormEl.reset(); renderTurnstile(registerFormContainer.querySelector('.cf-turnstile'));}
        }
        if(login2FASection) login2FASection.classList.add('hidden');
        loginEmailFor2FA = null;
        updateUnreadMessagesIndicatorUI(0);
    }
}
async function fetchAppConfigAndInitialize() {
    try {
        const response = await apiCall('/api/config');
        if (response.ok && response.data.turnstileSiteKey) {
            TURNSTILE_SITE_KEY = response.data.turnstileSiteKey;
        }
    } catch (error) { }
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
document.addEventListener('DOMContentLoaded', () => {
    messageArea = document.getElementById('message-area');
    authSection = document.getElementById('auth-section');
    loggedInSection = document.getElementById('logged-in-section');
    adminSection = document.getElementById('admin-section');
    loginFormEl = document.getElementById('login-form-el');
    registerFormEl = document.getElementById('register-form-el');
    appWrapper = document.getElementById('app-wrapper');
    topBarUserEmailEl = document.getElementById('top-bar-user-email');
    topBarUserUsernameEl = document.getElementById('top-bar-user-username');
    topBarUserInfoEl = document.getElementById('top-bar-user-info');
    topBarAuthButtonsEl = document.getElementById('top-bar-auth-buttons');
    topBarLogoutButtonEl = document.getElementById('top-bar-logout-button');
    userMenuButtonEl = document.getElementById('user-menu-button');
    userDropdownMenuEl = document.getElementById('user-dropdown-menu');
    topBarAccountLinkEl = document.getElementById('top-bar-account-link');
    topBarAdminLinkEl = document.getElementById('top-bar-admin-link');
    topBarMessagingButton = document.getElementById('top-bar-messaging-button');
    sidebarEl = document.getElementById('sidebar');
    sidebarToggleEl = document.getElementById('sidebar-toggle');
    mainContentContainerEl = document.getElementById('main-content').querySelector('.container');
    sidebarOverlayEl = document.getElementById('sidebar-overlay');
    accountTabLinks = Array.from(document.querySelectorAll('#account-tabs .sidebar-link'));
    adminTabLinks = Array.from(document.querySelectorAll('#admin-tabs .sidebar-link'));
    tabPanes = Array.from(document.querySelectorAll('.tab-pane'));
    themeToggleButton = document.getElementById('theme-toggle-button');
    themeToggleDarkIcon = document.getElementById('theme-toggle-dark-icon');
    themeToggleLightIcon = document.getElementById('theme-toggle-light-icon');
    unreadMessagesIndicator = document.getElementById('unread-messages-indicator');
    let isDarkMode = localStorage.getItem('theme') === 'dark' || (!localStorage.getItem('theme') && window.matchMedia('(prefers-color-scheme: dark)').matches);
    applyTheme(isDarkMode);
    if (themeToggleButton) {
        themeToggleButton.addEventListener('click', () => {
            isDarkMode = !isDarkMode;
            localStorage.setItem('theme', isDarkMode ? 'dark' : 'light');
            applyTheme(isDarkMode);
        });
    }
    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', e => {
        if (localStorage.getItem('theme') === null) {
            isDarkMode = e.matches;
            applyTheme(isDarkMode);
        }
    });
    [...accountTabLinks, ...adminTabLinks].forEach(link => {
        link.addEventListener('click', (event) => {
        });
    });
    if (topBarMessagingButton) {
        topBarMessagingButton.addEventListener('click', (e) => {
            e.preventDefault();
            window.location.pathname = '/user/messaging';
        });
    }
    if (sidebarToggleEl) sidebarToggleEl.addEventListener('click', toggleSidebar);
    if (sidebarOverlayEl) sidebarOverlayEl.addEventListener('click', toggleSidebar);
    if (userMenuButtonEl && userDropdownMenuEl) {
        userMenuButtonEl.addEventListener('click', (event) => {
            event.stopPropagation();
            userDropdownMenuEl.classList.toggle('hidden');
        });
        document.addEventListener('click', (event) => {
            if (!userDropdownMenuEl.classList.contains('hidden') && !userMenuButtonEl.contains(event.target) && !userDropdownMenuEl.contains(event.target)) {
                userDropdownMenuEl.classList.add('hidden');
            }
        });
    }
    if (topBarAccountLinkEl) {
        topBarAccountLinkEl.addEventListener('click', (e) => {
            e.preventDefault();
            window.location.pathname = '/user/profile';
            if (userDropdownMenuEl) userDropdownMenuEl.classList.add('hidden');
        });
    }
    if (topBarAdminLinkEl) {
        topBarAdminLinkEl.addEventListener('click', (e) => {
            e.preventDefault();
            window.location.pathname = '/user/admin/users';
            if (userDropdownMenuEl) userDropdownMenuEl.classList.add('hidden');
        });
    }
    if (loginFormEl) loginFormEl.addEventListener('submit', (event) => handleAuth(event, 'login'));
    if (registerFormEl) registerFormEl.addEventListener('submit', (event) => handleAuth(event, 'register'));
    if (topBarLogoutButtonEl) topBarLogoutButtonEl.addEventListener('click', handleLogout);
    fetchAppConfigAndInitialize();
});
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
    } else {
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
            if (type === 'login' || (type === 'login' && loginEmailFor2FA) || (data.twoFactorRequired === undefined)) {
                 window.location.href = (data.is_admin === true) ? '/user/admin/users' : '/user/profile';
            } else {
                 window.location.href = '/user/login?registered=true';
            }
        }
    } else {
        showMessage(data.error || ('操作失败 (' + status + ')'), 'error', data.details ? true : false);
        if (type === 'login' && loginEmailFor2FA && status !== 401 && login2FASection) { login2FASection.classList.remove('hidden'); }
        else if (status === 401 && data.error === '两步验证码无效' && login2FASection) {
            login2FASection.classList.remove('hidden'); if(loginTotpCodeInput) { loginTotpCodeInput.value = ''; loginTotpCodeInput.focus(); }
        } else if (login2FASection) { login2FASection.classList.add('hidden'); loginEmailFor2FA = null; }
    }
};
window.handleLogout = async function() {
    clearMessages();
    if (userPresenceSocket && userPresenceSocket.readyState === WebSocket.OPEN) {
        userPresenceSocket.close();
    }
    if (typeof window.closeActiveConversationSocket === 'function') {
        window.closeActiveConversationSocket();
    }
    await apiCall('/api/logout', 'POST');
    currentUserData = null;
    window.location.href = '/user/login';
};
window.turnstileCallbackLogin = function(token) { };
window.turnstileCallbackRegister = function(token) { };
window.turnstileCallbackPasteApi = function(token) { };
window.turnstileCallbackCloudPc = function(token) { };
window.turnstileCallbackOauthClient = function(token) { };
window.copyToClipboard = function(text, itemNameToCopy = '内容') {
    if (!text) { showMessage('没有可复制的'+itemNameToCopy+'。', 'warning'); return; }
    navigator.clipboard.writeText(text).then(() => {
         showMessage(itemNameToCopy + '已复制到剪贴板！', 'success');
    }).catch(err => {
        showMessage('复制失败: ' + err, 'error');
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
window.apiCall = apiCall;
window.showMessage = showMessage;
window.clearMessages = clearMessages;
window.renderTurnstile = renderTurnstile;
window.removeTurnstile = removeTurnstile;
window.resetTurnstileInContainer = resetTurnstileInContainer;
window.checkLoginStatus = checkLoginStatus;
window.isValidEmail = function(email) {
    if (typeof email !== 'string') return false;
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
};
window.updateUnreadMessagesIndicatorUI = updateUnreadMessagesIndicatorUI;
