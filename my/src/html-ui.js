export function generateHtmlUi(currentPath = '/', env = {}) {
    const showLogin = currentPath === '/' || currentPath === '/user/login';
    const showRegister = currentPath === '/user/register';
    const showAccountSection = currentPath.startsWith('/user/') && !showLogin && !showRegister && currentPath !== '/user/help' && !currentPath.startsWith('/user/admin');
    const showAdminSection = currentPath.startsWith('/user/admin');
    const authSectionVisible = showLogin || showRegister;
    const siteName = "用户中心";
    const faviconDataUri = "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'%3E%3Ctext y='.9em' font-size='90'%3E👤%3C/text%3E%3C/svg%3E";
    const cdnBaseUrl = env.CDN_BASE_URL || "https://cdn.qmwneb946.dpdns.org";

    // Standard Icons (some might be replaced by user's new SVGs)
    const menuIcon = `<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" class="h-6 w-6"><path stroke-linecap="round" stroke-linejoin="round" d="M3.75 6.75h16.5M3.75 12h16.5m-16.5 5.25h16.5" /></svg>`;
    const userIcon = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" class="h-5 w-5 mr-1"><path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-5.5-2.5a2.5 2.5 0 11-5 0 2.5 2.5 0 015 0zM10 12a5.99 5.99 0 00-4.793 2.39A6.483 6.483 0 0010 16.5a6.483 6.483 0 004.793-2.11A5.99 5.99 0 0010 12z" clip-rule="evenodd" /></svg>`;
    const moonIcon = `<svg id="theme-toggle-dark-icon" class="h-5 w-5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"></path></svg>`;
    const messageIcon = `<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" class="h-5 w-5"><path stroke-linecap="round" stroke-linejoin="round" d="M2.25 12.76c0 1.6 1.123 2.994 2.707 3.227 1.087.16 2.185.283 3.293.369V21l4.076-4.076a1.526 1.526 0 011.037-.443 48.282 48.282 0 005.68-.494c1.584-.233 2.707-1.626 2.707-3.228V6.741c0-1.602-1.123-2.995-2.707-3.228A48.394 48.394 0 0012 3c-2.392 0-4.744.175-7.043.513C3.373 3.746 2.25 5.14 2.25 6.741v6.018z" /></svg>`;
    const warningIconLarge = `<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" class="w-16 h-16 text-yellow-500"><path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.008v.008H12v-.008z" /></svg>`;
    const mailIcon = `<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" class="h-6 w-6 mr-2"><path stroke-linecap="round" stroke-linejoin="round" d="M21.75 6.75v10.5a2.25 2.25 0 01-2.25 2.25h-15a2.25 2.25 0 01-2.25-2.25V6.75m19.5 0A2.25 2.25 0 0019.5 4.5h-15a2.25 2.25 0 00-2.25 2.25m19.5 0v.243a2.25 2.25 0 01-1.07 1.916l-7.5 4.615a2.25 2.25 0 01-2.36 0L3.32 8.91a2.25 2.25 0 01-1.07-1.916V6.75" /></svg>`;

    // User provided SVGs (replacing class="size-6" with "h-5 w-5 mr-2" or "h-5 w-5")
    const adminIcon = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" fill="currentColor" class="size-4"><path fill-rule="evenodd" d="M6.455 1.45A.5.5 0 0 1 6.952 1h2.096a.5.5 0 0 1 .497.45l.186 1.858a4.996 4.996 0 0 1 1.466.848l1.703-.769a.5.5 0 0 1 .639.206l1.047 1.814a.5.5 0 0 1-.14.656l-1.517 1.09a5.026 5.026 0 0 1 0 1.694l1.516 1.09a.5.5 0 0 1 .141.656l-1.047 1.814a.5.5 0 0 1-.639.206l-1.703-.768c-.433.36-.928.649-1.466.847l-.186 1.858a.5.5 0 0 1-.497.45H6.952a.5.5 0 0 1-.497-.45l-.186-1.858a4.993 4.993 0 0 1-1.466-.848l-1.703.769a.5.5 0 0 1-.639-.206l-1.047-1.814a.5.5 0 0 1 .14-.656l1.517-1.09a5.033 5.033 0 0 1 0-1.694l-1.516-1.09a.5.5 0 0 1-.141-.656L2.46 3.593a.5.5 0 0 1 .639-.206l1.703.769c.433-.36.928-.65 1.466-.848l.186-1.858Zm-.177 7.567-.022-.037a2 2 0 0 1 3.466-1.997l.022.037a2 2 0 0 1-3.466 1.997Z" clip-rule="evenodd" /></svg>`; // This is Question Mark Circle, per user's "设置的svg"
    const sunIcon = `<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" class="h-5 w-5"><path stroke-linecap="round" stroke-linejoin="round" d="M12 3v2.25m6.364.386-1.591 1.591M21 12h-2.25m-.386 6.364-1.591-1.591M12 18.75V21m-4.773-4.227-1.591 1.591M5.25 12H3m4.227-4.773L5.636 5.636M15.75 12a3.75 3.75 0 1 1-7.5 0 3.75 3.75 0 0 1 7.5 0Z" /></svg>`;
    const helpIcon = `<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" class="h-5 w-5 mr-2"><path stroke-linecap="round" stroke-linejoin="round" d="M9.879 7.519c1.171-1.025 3.071-1.025 4.242 0 1.172 1.025 1.172 2.687 0 3.712-.203.179-.43.326-.67.442-.745.361-1.45.999-1.45 1.827v.75M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Zm-9 5.25h.008v.008H12v-.008Z" /></svg>`;
    const oauthIcon = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" class="h-5 w-5 mr-2"><path fill-rule="evenodd" d="M8.603 3.799A4.49 4.49 0 0 1 12 2.25c1.357 0 2.573.6 3.397 1.549a4.49 4.49 0 0 1 3.498 1.307 4.491 4.491 0 0 1 1.307 3.497A4.49 4.49 0 0 1 21.75 12a4.49 4.49 0 0 1-1.549 3.397 4.491 4.491 0 0 1-1.307 3.497 4.491 4.491 0 0 1-3.497 1.307A4.49 4.49 0 0 1 12 21.75a4.49 4.49 0 0 1-3.397-1.549 4.49 4.49 0 0 1-3.498-1.306 4.491 4.491 0 0 1-1.307-3.498A4.49 4.49 0 0 1 2.25 12c0-1.357.6-2.573 1.549-3.397a4.49 4.49 0 0 1 1.307-3.497 4.49 4.49 0 0 1 3.497-1.307Zm7.007 6.387a.75.75 0 1 0-1.22-.872l-3.236 4.53L9.53 12.22a.75.75 0 0 0-1.06 1.06l2.25 2.25a.75.75 0 0 0 1.14-.094l3.75-5.25Z" clip-rule="evenodd" /></svg>`;
    const apiKeyIcon = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" class="h-5 w-5 mr-2"><path fill-rule="evenodd" d="M15.75 1.5a6.75 6.75 0 0 0-6.651 7.906c.067.39-.032.717-.221.906l-6.5 6.499a3 3 0 0 0-.878 2.121v2.818c0 .414.336.75.75.75H6a.75.75 0 0 0 .75-.75v-1.5h1.5A.75.75 0 0 0 9 19.5V18h1.5a.75.75 0 0 0 .53-.22l2.658-2.658c.19-.189.517-.288.906-.22A6.75 6.75 0 1 0 15.75 1.5Zm0 3a.75.75 0 0 0 0 1.5A2.25 2.25 0 0 1 18 8.25a.75.75 0 0 0 1.5 0 3.75 3.75 0 0 0-3.75-3.75Z" clip-rule="evenodd" /></svg>`;
    const personalInfoIcon = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" class="h-5 w-5 mr-2"><path fill-rule="evenodd" d="M18.685 19.097A9.723 9.723 0 0 0 21.75 12c0-5.385-4.365-9.75-9.75-9.75S2.25 6.615 2.25 12a9.723 9.723 0 0 0 3.065 7.097A9.716 9.716 0 0 0 12 21.75a9.716 9.716 0 0 0 6.685-2.653Zm-12.54-1.285A7.486 7.486 0 0 1 12 15a7.486 7.486 0 0 1 5.855 2.812A8.224 8.224 0 0 1 12 20.25a8.224 8.224 0 0 1-5.855-2.438ZM15.75 9a3.75 3.75 0 1 1-7.5 0 3.75 3.75 0 0 1 7.5 0Z" clip-rule="evenodd" /></svg>`;
    const securityIcon = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" class="h-5 w-5 mr-2"><path fill-rule="evenodd" d="M12 1.5a5.25 5.25 0 0 0-5.25 5.25v3a3 3 0 0 0-3 3v6.75a3 3 0 0 0 3 3h10.5a3 3 0 0 0 3-3v-6.75a3 3 0 0 0-3-3v-3c0-2.9-2.35-5.25-5.25-5.25Zm3.75 8.25v-3a3.75 3.75 0 1 0-7.5 0v3h7.5Z" clip-rule="evenodd" /></svg>`;

    return `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${siteName}</title>
    <link rel="icon" href="${faviconDataUri}">
    <link rel="stylesheet" href="${cdnBaseUrl}/css/style.css">
    <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
    <script src="https://cdn.jsdelivr.net/npm/qrcodejs@1.0.0/qrcode.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js" defer></script>
    <script src="https://cdn.jsdelivr.net/npm/dompurify/dist/purify.min.js" defer></script>
    <style>
        .hidden { display: none !important; }
        .modal {
            position: fixed; top: 0; left: 0; width: 100%; height: 100%;
            background-color: rgba(0,0,0,0.6); display: flex;
            justify-content: center; align-items: center; z-index: 2000;
            opacity: 0; visibility: hidden; transition: opacity 0.3s ease, visibility 0s linear 0.3s;
        }
        .modal.active { opacity: 1; visibility: visible; transition: opacity 0.3s ease; }
        .modal-content {
            background-color: var(--current-surface-color); color: var(--current-text-color);
            padding: 25px 30px; border-radius: var(--border-radius);
            box-shadow: 0 5px 15px rgba(0,0,0,0.3); width: 90%; max-width: 500px;
            transform: translateY(-20px); transition: transform 0.3s ease;
        }
        .modal.active .modal-content { transform: translateY(0); }
        .modal-content h4 { margin-top: 0; text-align: left; font-size: 1.4em; color: var(--current-heading-color); }
        .modal-buttons { margin-top: 25px; text-align: right; }
        .modal-buttons button { margin-left: 10px; }
        .license-code-list { list-style-type: none; padding-left: 0; max-height: 200px; overflow-y: auto; border: 1px solid var(--current-border-color); border-radius: var(--border-radius); padding: 10px; background-color: var(--current-bg-color); }
        .license-code-list li { padding: 5px 0; border-bottom: 1px dashed var(--current-border-color); font-family: var(--font-family-mono); font-size: 0.9em;}
        .license-code-list li:last-child { border-bottom: none; }
        .admin-panel-table { width: 100%; border-collapse: collapse; margin-top: 20px; font-size: 0.9em; }
        .admin-panel-table th, .admin-panel-table td { border: 1px solid var(--current-border-color); padding: 8px 12px; text-align: left; }
        .admin-panel-table th { background-color: var(--current-surface-color); font-weight: 600; }
        .admin-panel-table tr:nth-child(even) { background-color: color-mix(in srgb, var(--current-surface-color) 95%, var(--current-bg-color));}
        .admin-panel-table td code { background-color: color-mix(in srgb, var(--current-text-color) 10%, transparent); padding: 2px 4px; border-radius: 3px; font-family: var(--font-family-mono); }
        .status-active { color: var(--success-color); font-weight: bold; }
        .status-inactive, .status-suspended { color: var(--danger-color); font-weight: bold; }
        .admin-actions button { margin-right: 5px; }
    </style>
</head>
<body class="font-sans antialiased">
    <div id="app-wrapper" class="app-wrapper">
        <header id="top-bar" class="top-bar">
            <div class="top-bar-left">
                <button id="sidebar-toggle" class="sidebar-toggle-button" aria-label="切换导航菜单">
                    ${menuIcon}
                </button>
                <span class="site-title">${siteName}</span>
            </div>
            <div class="top-bar-right">
                <button type="button" id="theme-toggle-button" aria-label="切换主题" class="theme-toggle-button">
                    ${sunIcon}
                    ${moonIcon}
                </button>
                <button type="button" id="top-bar-messaging-button" aria-label="私信" class="messaging-button hidden">
                    ${messageIcon}
                    <span id="unread-messages-indicator" class="unread-badge hidden"></span>
                </button>
                <div id="top-bar-auth-buttons" class="auth-actions hidden">
                    <a href="/user/register" class="button secondary small">注册</a>
                    <a href="/user/login" class="button primary small">登录</a>
                </div>
                <div id="top-bar-user-info" class="user-info-dropdown hidden">
                    <button id="user-menu-button" class="user-menu-button">
                        ${userIcon}
                        <span class="username-text" id="top-bar-user-username"></span>
                    </button>
                    <div id="user-dropdown-menu" class="dropdown-menu hidden">
                        <div class="dropdown-user-email" id="top-bar-user-email"></div>
                        <hr class="dropdown-divider">
                        <a href="/user/profile" id="top-bar-account-link" class="dropdown-item">${personalInfoIcon}账户设置</a>
                        <a href="/user/admin" id="top-bar-admin-link" class="dropdown-item hidden">${adminIcon}管理员面板</a>
                        <a href="/user/help" class="dropdown-item">${helpIcon}帮助与API示例</a>
                        <button type="button" class="dropdown-item logout" id="top-bar-logout-button">安全登出</button>
                    </div>
                </div>
            </div>
        </header>
        <aside id="sidebar" class="sidebar">
            <nav class="sidebar-nav">
                <ul id="account-tabs">
                    <li><a href="/user/profile" id="nav-profile" class="sidebar-link" data-pane-id="tab-content-personal-info">${personalInfoIcon}个人信息</a></li>
                    <li><a href="/user/security" id="nav-security" class="sidebar-link" data-pane-id="tab-content-security-settings">${securityIcon}安全设置</a></li>
                    <li><a href="/user/api-keys" id="nav-api-keys" class="sidebar-link" data-pane-id="tab-content-api-keys">${apiKeyIcon}获取/查看密钥</a></li>
                    <li><a href="/user/applications" id="nav-applications" class="sidebar-link" data-pane-id="tab-content-my-applications">${oauthIcon}我的应用</a></li>
                </ul>
                <ul id="admin-tabs" class="hidden" style="margin-top: 20px; border-top: 1px solid var(--current-border-color); padding-top:10px;">
                     <li><a href="/user/admin/users" id="nav-admin-users" class="sidebar-link" data-pane-id="tab-content-admin-users">${adminIcon}用户管理</a></li>
                     <li><a href="/user/admin/apps" id="nav-admin-apps" class="sidebar-link" data-pane-id="tab-content-admin-apps">${adminIcon}应用管理</a></li>
                </ul>
            </nav>
        </aside>
        <div id="sidebar-overlay" class="sidebar-overlay hidden"></div>
        <main id="main-content" class="main-content">
            <div class="container">
                <div id="message-area" class="message hidden" role="alert"></div>
                <div id="auth-section" class="auth-section ${authSectionVisible ? '' : 'hidden'}">
                    <div id="login-form" class="form-container ${showLogin ? '' : 'hidden'}">
                        <h2>用户登录</h2>
                        <form id="login-form-el">
                            <div class="form-group"><label for="login-identifier">邮箱或用户名</label><input type="text" id="login-identifier" name="identifier" required autocomplete="username email" placeholder="请输入您的邮箱或用户名"></div>
                            <div class="form-group"><label for="login-password">密码</label><input type="password" id="login-password" name="password" required autocomplete="current-password" placeholder="请输入密码"></div>
                            <div id="login-2fa-section" class="form-group hidden"><label for="login-totp-code">两步验证码</label><input type="text" id="login-totp-code" name="totpCode" pattern="\\d{6}" maxlength="6" placeholder="请输入6位验证码"></div>
                            <div class="cf-turnstile" data-sitekey="${env.TURNSTILE_SITE_KEY || '1x00000000000000000000AA'}" data-callback="turnstileCallbackLogin"></div>
                            <button type="submit" class="button primary full-width">登录</button>
                        </form>
                        <div class="toggle-link">还没有账户？ <a href="/user/register">立即注册</a></div>
                    </div>
                    <div id="register-form" class="form-container ${showRegister ? '' : 'hidden'}">
                        <h2>新用户注册</h2>
                        <form id="register-form-el">
                            <div class="form-group"><label for="register-username">用户名</label><input type="text" id="register-username" name="username" required minlength="3" maxlength="30" placeholder="3-30位字符，可包含字母、数字、_-"></div>
                            <div class="form-group"><label for="register-email">邮箱地址</label><input type="email" id="register-email" name="email" required autocomplete="email" placeholder="例如：user@example.com"></div>
                            <div class="form-group"><label for="register-phone">手机号码 (可选)</label><input type="tel" id="register-phone" name="phoneNumber" autocomplete="tel" placeholder="例如：+8613800138000"></div>
                            <div class="form-group"><label for="register-password">设置密码 (至少6位)</label><input type="password" id="register-password" name="password" required minlength="6" autocomplete="new-password" placeholder="请输入至少6位密码"></div>
                            <div class="form-group"><label for="register-confirm-password">确认密码</label><input type="password" id="register-confirm-password" name="confirmPassword" required minlength="6" autocomplete="new-password" placeholder="请再次输入密码"></div>
                            <div class="cf-turnstile" data-sitekey="${env.TURNSTILE_SITE_KEY || '1x00000000000000000000AA'}" data-callback="turnstileCallbackRegister"></div>
                            <button type="submit" class="button primary full-width">创建账户</button>
                        </form>
                        <div class="toggle-link">已经有账户了？ <a href="/user/login">返回登录</a></div>
                    </div>
                </div>
                <div id="logged-in-section" class="account-content ${showAccountSection ? '' : 'hidden'}">
                    <div id="tab-content-personal-info" class="tab-pane hidden" data-path="/user/profile">
                        <h3>${personalInfoIcon}个人信息修改</h3>
                        <form id="update-profile-form" class="content-form">
                            <div class="form-group"><label for="profile-username">用户名</label><input type="text" id="profile-username" name="username" required minlength="3" maxlength="30" placeholder="3-30位字符"></div>
                            <div class="form-group"><label for="profile-phone">手机号码 (可选)</label><input type="tel" id="profile-phone" name="phoneNumber" placeholder="例如：+8613800138000"></div>
                            <div class="form-group"><label for="profile-email">邮箱地址 (不可修改)</label><input type="email" id="profile-email" name="email" readonly disabled></div>
                            <button type="submit" class="button primary">保存个人信息</button>
                        </form>
                    </div>
                    <div id="tab-content-security-settings" class="tab-pane hidden" data-path="/user/security">
                        <h3>${securityIcon}安全设置</h3>
                        <ul class="security-settings-list">
                            <li class="security-setting-item">
                                <div class="setting-entry" data-target="change-password-content-panel">
                                    <span class="entry-title">修改密码</span>
                                    <span class="entry-arrow">▼</span>
                                </div>
                                <div id="change-password-content-panel" class="setting-content-panel hidden">
                                    <form id="change-password-form" class="content-form">
                                        <div class="form-group"><label for="current-password">当前密码</label><input type="password" id="current-password" name="currentPassword" required autocomplete="current-password" placeholder="请输入您当前的密码"></div>
                                        <div class="form-group"><label for="new-password">新密码 (至少6位)</label><input type="password" id="new-password" name="newPassword" required minlength="6" autocomplete="new-password" placeholder="请输入新的密码"></div>
                                        <button type="submit" class="button secondary">确认修改密码</button>
                                    </form>
                                </div>
                            </li>
                            <li class="security-setting-item">
                                <div class="setting-entry" data-target="2fa-content-panel">
                                    <span class="entry-title">两步验证 (2FA)</span>
                                    <span class="entry-status" id="2fa-entry-status">(未知)</span>
                                    <span class="entry-arrow">▼</span>
                                </div>
                                <div id="2fa-content-panel" class="setting-content-panel hidden">
                                    <p class="description-text">使用两步验证码可以帮您双重保护账户安全。</p>
                                    <div id="2fa-status-section" class="status-display">当前状态: <span id="2fa-current-status">未知</span></div>
                                    <div id="2fa-controls" style="margin-bottom: 15px;">
                                        <button type="button" id="btn-init-enable-2fa" class="button success small hidden">启用两步验证</button>
                                        <button type="button" id="btn-disable-2fa" class="button danger small hidden">禁用两步验证</button>
                                    </div>
                                    <div id="2fa-setup-section" class="hidden" style="margin-top:20px;">
                                        <p>1. 使用您的身份验证器应用扫描二维码或手动输入密钥。</p>
                                        <div style="text-align: center; margin: 15px 0;"><div id="qrcode-display"></div></div>
                                        <p>密钥链接: <code id="otpauth-uri-text-display" class="otpauth-uri-text"></code></p>
                                        <input type="hidden" id="2fa-temp-secret">
                                        <div class="form-group" style="margin-top:10px;"><label for="2fa-setup-code">6位验证码</label><input type="text" id="2fa-setup-code" name="totpCode" pattern="\\d{6}" maxlength="6" placeholder="请输入验证码"></div>
                                        <div class="form-actions">
                                            <button type="button" id="btn-complete-enable-2fa" class="button success">验证并启用</button>
                                            <button type="button" id="btn-cancel-2fa-setup" class="button secondary">取消</button>
                                        </div>
                                    </div>
                                </div>
                            </li>
                        </ul>
                    </div>
                    <div id="tab-content-api-keys" class="tab-pane hidden" data-path="/user/api-keys">
                        <h3>${apiKeyIcon}获取/查看密钥</h3>
                        <ul class="security-settings-list">
                            <li class="security-setting-item">
                                <div class="setting-entry" data-target="paste-api-key-content-panel">
                                    <span class="entry-title">云剪贴板 API 密钥</span>
                                    <span class="entry-arrow">▼</span>
                                </div>
                                <div id="paste-api-key-content-panel" class="setting-content-panel hidden">
                                    <p class="description-text">API 密钥名称将自动生成，仅拥有文本和文件权限。</p>
                                    <p class="description-text">访问云剪贴板服务：<a href="http://go.qmwneb946.dpdns.org/?LinkId=37" target="_blank" rel="noopener noreferrer" class="external-link">http://go.qmwneb946.dpdns.org/?LinkId=37</a></p>
                                    <form id="create-paste-api-key-form" class="content-form" style="margin-top:15px;">
                                        <div class="cf-turnstile" data-sitekey="${env.TURNSTILE_SITE_KEY || '1x00000000000000000000AA'}" data-callback="turnstileCallbackPasteApi"></div>
                                        <button type="submit" class="button success">创建云剪贴板 API 密钥</button>
                                    </form>
                                    <div id="newly-created-api-key-display" class="hidden api-key-display" style="margin-top:15px;">
                                        <h5>新创建的云剪贴板 API 密钥：</h5>
                                        <div class="api-key-value-container">
                                            <input type="text" id="new-api-key-value" readonly><button type="button" class="button small secondary" onclick="copyToClipboard(document.getElementById('new-api-key-value').value, '云剪贴板 API 密钥')">复制</button>
                                        </div>
                                    </div>
                                </div>
                            </li>
                            <li class="security-setting-item">
                                <div class="setting-entry" data-target="cloud-pc-key-content-panel">
                                    <span class="entry-title">Cloud PC 密钥</span>
                                    <span class="entry-status" id="cloud-pc-key-entry-status">(点击展开查看状态)</span>
                                    <span class="entry-arrow">▼</span>
                                </div>
                                <div id="cloud-pc-key-content-panel" class="setting-content-panel hidden">
                                    <div id="cloud-pc-key-status-area" class="status-display">正在加载 Cloud PC 密钥状态...</div>
                                     <p class="description-text">访问 Cloud PC 服务：<a href="http://go.qmwneb946.dpdns.org/?LinkId=17" target="_blank" rel="noopener noreferrer" class="external-link">http://go.qmwneb946.dpdns.org/?LinkId=17</a></p>
                                    <form id="create-cloud-pc-key-form" class="content-form hidden" style="margin-top:15px;">
                                        <p class="description-text">每位用户仅可创建一次，获得 1 次使用次数。</p>
                                        <div class="cf-turnstile" data-sitekey="${env.TURNSTILE_SITE_KEY || '1x00000000000000000000AA'}" data-callback="turnstileCallbackCloudPc"></div>
                                        <button type="submit" class="button success">创建 Cloud PC 密钥</button>
                                    </form>
                                    <div id="existing-cloud-pc-key-display" class="hidden api-key-display" style="margin-top:15px;">
                                        <h5>您的 Cloud PC 密钥：</h5>
                                        <div class="api-key-value-container">
                                            <input type="text" id="cloud-pc-api-key-value" readonly><button type="button" class="button small secondary" onclick="copyToClipboard(document.getElementById('cloud-pc-api-key-value').value, 'Cloud PC API 密钥')">复制</button>
                                        </div>
                                        <p>剩余使用次数: <strong id="cloud-pc-usage-count"></strong></p>
                                    </div>
                                </div>
                            </li>
                            <li class="security-setting-item">
                                <div class="setting-entry" data-target="greenhub-key-content-panel">
                                    <span class="entry-title">GreenHub 激活码</span>
                                    <span class="entry-arrow">▼</span>
                                </div>
                                <div id="greenhub-key-content-panel" class="setting-content-panel hidden">
                                    <p class="description-text">查看您已获取的 GreenHub 激活码。</p>
                                    <button type="button" id="btn-fetch-greenhub-keys" class="button primary">获取 GreenHub 激活码</button>
                                    <div id="greenhub-codes-display" style="margin-top:15px;">
                                        <p class="placeholder-text">点击按钮获取激活码。</p>
                                    </div>
                                </div>
                            </li>
                        </ul>
                    </div>
                    <div id="tab-content-my-applications" class="tab-pane hidden" data-path="/user/applications">
                        <h3>${oauthIcon}我的 OAuth 应用</h3>
                        <div class="setting-block">
                            <h4>注册新应用</h4>
                            <form id="register-oauth-client-form" class="content-form">
                                <div class="form-group"><label for="oauth-client-name">应用名称</label><input type="text" id="oauth-client-name" name="clientName" required maxlength="50" placeholder="例如：我的博客评论系统"></div>
                                <div class="form-group"><label for="oauth-client-website">应用主页 (可选)</label><input type="url" id="oauth-client-website" name="clientWebsite" maxlength="200" placeholder="例如：https://myblog.com"></div>
                                <div class="form-group"><label for="oauth-client-description">应用描述 (可选)</label><input type="text" id="oauth-client-description" name="clientDescription" maxlength="200" placeholder="简要描述您的应用"></div>
                                <div class="form-group"><label for="oauth-client-redirect-uri">回调地址 (Redirect URI)</label><input type="url" id="oauth-client-redirect-uri" name="redirectUri" required placeholder="例如：https://myblog.com/oauth/callback"><p class="input-hint">必须是 HTTPS 地址。</p></div>
                                <div class="cf-turnstile" data-sitekey="${env.TURNSTILE_SITE_KEY || '1x00000000000000000000AA'}" data-callback="turnstileCallbackOauthClient"></div>
                                <button type="submit" class="button success">注册应用</button>
                            </form>
                            <div id="new-oauth-client-credentials" class="hidden" style="margin-top: 20px;">
                                <h5 style="color: var(--primary-color);">应用注册成功！</h5>
                                <p class="description-text">请妥善保管您的应用凭据，特别是 <strong>客户端密钥 (Client Secret)</strong>，它将仅显示这一次。</p>
                                <div class="application-card">
                                    <p><strong>客户端 ID:</strong> <code id="new-client-id-display"></code> <button type="button" class="button small secondary" onclick="copyToClipboard(document.getElementById('new-client-id-display').textContent, '客户端 ID')">复制</button></p>
                                    <p><strong>客户端密钥:</strong> <code id="new-client-secret-display"></code> <button type="button" class="button small secondary" onclick="copyToClipboard(document.getElementById('new-client-secret-display').textContent, '客户端密钥')">复制</button></p>
                                </div>
                                <div class="new-client-secret-warning"><strong>重要提示:</strong> 客户端密钥非常敏感，请立即复制并安全存储。</div>
                            </div>
                        </div>
                        <hr class="section-divider">
                        <h4>已注册的应用</h4>
                        <div id="registered-oauth-clients-list"><p>正在加载应用列表...</p></div>
                    </div>
                    <div id="tab-content-messaging" class="tab-pane hidden" data-path="/user/messaging">
                        <div class="messaging-tab-header">
                            ${mailIcon}
                            <h3>个人私信</h3>
                        </div>
                        <div class="new-conversation-trigger" id="new-conversation-area-messaging">
                             <input type="email" id="new-conversation-email" placeholder="输入对方邮箱开始新对话...">
                             <button type="button" id="btn-start-new-conversation" class="button primary small">开始</button>
                        </div>
                        <div class="messaging-layout-new">
                            <div class="messaging-contacts-panel">
                                <div class="contact-search-bar">
                                    <input type="search" id="contact-search-input" placeholder="搜索联系人...">
                                </div>
                                <h4 class="recent-contacts-title">最近联系</h4>
                                <ul id="conversations-list" class="contact-list">
                                    <p class="placeholder-text">正在加载对话...</p>
                                </ul>
                            </div>
                            <div id="messages-area" class="message-display-panel">
                                <div id="messages-list" class="messages-list">
                                    <div id="messages-loading-indicator-wrapper" class="messages-loading-indicator-wrapper hidden"><div class="spinner"></div></div>
                                    <div id="load-more-messages-button-wrapper" class="load-more-messages-button-wrapper hidden">
                                        <button type="button" id="load-more-messages-button" class="button secondary small load-more-messages-button">加载更多...</button>
                                    </div>
                                    <div class="empty-messages-placeholder">
                                        ${warningIconLarge}
                                        <p>选择一个联系人开始聊天</p>
                                        <span>或通过上方搜索框发起新的对话。</span>
                                    </div>
                                </div>
                                <div id="message-input-area" class="message-input-area hidden">
                                    <textarea id="message-input" placeholder="输入消息..." rows="1"></textarea>
                                    <button type="button" id="btn-send-message" class="button primary">发送</button>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                <div id="admin-section" class="admin-content ${showAdminSection ? '' : 'hidden'}">
                    <div id="tab-content-admin-users" class="tab-pane hidden" data-path="/user/admin/users">
                        <h3>用户管理</h3>
                        <div id="admin-users-list-container">
                            <p>正在加载用户列表...</p>
                        </div>
                    </div>
                    <div id="tab-content-admin-apps" class="tab-pane hidden" data-path="/user/admin/apps">
                        <h3>OAuth 应用管理</h3>
                         <div id="admin-oauth-clients-list-container">
                            <p>正在加载应用列表...</p>
                        </div>
                    </div>
                </div>
            </div>
        </main>
    </div>
    <div id="edit-oauth-client-modal" class="modal hidden">
        <div class="modal-content">
            <h4 id="edit-oauth-client-modal-title">编辑应用信息</h4>
            <form id="edit-oauth-client-form">
                <input type="hidden" id="edit-client-id" name="clientId">
                <div class="form-group"><label for="edit-oauth-client-name">应用名称</label><input type="text" id="edit-oauth-client-name" name="clientName" required maxlength="50"></div>
                <div class="form-group"><label for="edit-oauth-client-website">应用主页 (可选)</label><input type="url" id="edit-oauth-client-website" name="clientWebsite" maxlength="200"></div>
                <div class="form-group"><label for="edit-oauth-client-description">应用描述 (可选)</label><input type="text" id="edit-oauth-client-description" name="clientDescription" maxlength="200"></div>
                <div class="form-group"><label for="edit-oauth-client-redirect-uri">回调地址</label><input type="url" id="edit-oauth-client-redirect-uri" name="redirectUri" required><p class="input-hint">必须是 HTTPS 地址。</p></div>
                <div class="modal-buttons">
                    <button type="button" id="btn-cancel-edit-oauth-client" class="button secondary">取消</button>
                    <button type="submit" class="button success">保存更改</button>
                </div>
            </form>
        </div>
    </div>
    <script src="${cdnBaseUrl}/js/main.js" defer></script>
    <script src="${cdnBaseUrl}/js/ui-personal-info.js" defer></script>
    <script src="${cdnBaseUrl}/js/ui-security-settings.js" defer></script>
    <script src="${cdnBaseUrl}/js/ui-api-keys.js" defer></script>
    <script src="${cdnBaseUrl}/js/ui-oauth-apps.js" defer></script>
    <script src="${cdnBaseUrl}/js/ui-messaging.js" defer></script>
    <script src="${cdnBaseUrl}/js/ui-admin.js" defer></script>
</body>
</html>`;
}
export function generateHelpPageHtml(env = {}) {
    const siteName = "用户中心";
    const faviconDataUri = "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'%3E%3Ctext y='.9em' font-size='90'%3E👤%3C/text%3E%3C/svg%3E";
    const cdnBaseUrl = env.CDN_BASE_URL || "https://cdn.qmwneb946.dpdns.org";
    const menuIcon = `<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" class="h-6 w-6"><path stroke-linecap="round" stroke-linejoin="round" d="M3.75 6.75h16.5M3.75 12h16.5m-16.5 5.25h16.5" /></svg>`;
    const userIcon = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" class="h-5 w-5 mr-1"><path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-5.5-2.5a2.5 2.5 0 11-5 0 2.5 2.5 0 015 0zM10 12a5.99 5.99 0 00-4.793 2.39A6.483 6.483 0 0010 16.5a6.483 6.483 0 004.793-2.11A5.99 5.99 0 0010 12z" clip-rule="evenodd" /></svg>`;
    const sunIcon = `<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" class="h-5 w-5"><path stroke-linecap="round" stroke-linejoin="round" d="M12 3v2.25m6.364.386-1.591 1.591M21 12h-2.25m-.386 6.364-1.591-1.591M12 18.75V21m-4.773-4.227-1.591 1.591M5.25 12H3m4.227-4.773L5.636 5.636M15.75 12a3.75 3.75 0 1 1-7.5 0 3.75 3.75 0 0 1 7.5 0Z" /></svg>`;
    const moonIcon = `<svg id="theme-toggle-dark-icon" class="h-5 w-5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"></path></svg>`;
    const messageIcon = `<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" class="h-5 w-5"><path stroke-linecap="round" stroke-linejoin="round" d="M2.25 12.76c0 1.6 1.123 2.994 2.707 3.227 1.087.16 2.185.283 3.293.369V21l4.076-4.076a1.526 1.526 0 011.037-.443 48.282 48.282 0 005.68-.494c1.584-.233 2.707-1.626 2.707-3.228V6.741c0-1.602-1.123-2.995-2.707-3.228A48.394 48.394 0 0012 3c-2.392 0-4.744.175-7.043.513C3.373 3.746 2.25 5.14 2.25 6.741v6.018z" /></svg>`;
    const adminIcon = `<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" class="h-5 w-5 mr-2"><path stroke-linecap="round" stroke-linejoin="round" d="M9.879 7.519c1.171-1.025 3.071-1.025 4.242 0 1.172 1.025 1.172 2.687 0 3.712-.203.179-.43.326-.67.442-.745.361-1.45.999-1.45 1.827v.75M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Zm-9 5.25h.008v.008H12v-.008Z" /></svg>`; // Question mark circle for admin per user
    const helpIcon = `<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" class="h-5 w-5 mr-2"><path stroke-linecap="round" stroke-linejoin="round" d="M9.879 7.519c1.171-1.025 3.071-1.025 4.242 0 1.172 1.025 1.172 2.687 0 3.712-.203.179-.43.326-.67.442-.745.361-1.45.999-1.45 1.827v.75M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Zm-9 5.25h.008v.008H12v-.008Z" /></svg>`;
    const personalInfoIcon = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" class="h-5 w-5 mr-2"><path fill-rule="evenodd" d="M18.685 19.097A9.723 9.723 0 0 0 21.75 12c0-5.385-4.365-9.75-9.75-9.75S2.25 6.615 2.25 12a9.723 9.723 0 0 0 3.065 7.097A9.716 9.716 0 0 0 12 21.75a9.716 9.716 0 0 0 6.685-2.653Zm-12.54-1.285A7.486 7.486 0 0 1 12 15a7.486 7.486 0 0 1 5.855 2.812A8.224 8.224 0 0 1 12 20.25a8.224 8.224 0 0 1-5.855-2.438ZM15.75 9a3.75 3.75 0 1 1-7.5 0 3.75 3.75 0 0 1 7.5 0Z" clip-rule="evenodd" /></svg>`;

    return `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>帮助与API示例 - ${siteName}</title>
    <link rel="icon" href="${faviconDataUri}">
    <link rel="stylesheet" href="${cdnBaseUrl}/css/style.css">
    <style>
        .help-content { padding: 20px; }
        .api-usage-section pre {
            background-color: color-mix(in srgb, var(--current-bg-color) 95%, var(--current-surface-color));
            color: var(--current-text-color);
            padding: 15px; border-radius: var(--border-radius); overflow-x: auto;
            font-family: var(--font-family-mono); font-size: 0.875em;
            border: 1px solid var(--current-border-color); margin-bottom: 15px;
        }
        .api-usage-section code.inline-code {
            background-color: color-mix(in srgb, var(--current-text-color) 10%, transparent);
            padding: 2px 5px; border-radius: 3px; font-family: var(--font-family-mono);
        }
         hr.section-divider { border: none; border-top: 1px solid var(--current-border-color); margin: 30px 0; }
         body.dark-mode .api-usage-section pre {
            background-color: color-mix(in srgb, var(--current-bg-color) 95%, var(--current-surface-color));
         }
         .app-wrapper.help-page-layout .sidebar { display: none; }
         .app-wrapper.help-page-layout .main-content { margin-left: 0; }
    </style>
</head>
<body class="font-sans antialiased">
    <div id="app-wrapper" class="app-wrapper help-page-layout">
        <header id="top-bar" class="top-bar">
            <div class="top-bar-left">
                <button id="sidebar-toggle" class="sidebar-toggle-button" aria-label="切换导航菜单">
                    ${menuIcon}
                </button>
                <a href="/" class="site-title" style="margin-left:0;">${siteName}</a>
            </div>
            <div class="top-bar-right">
                <button type="button" id="theme-toggle-button" aria-label="切换主题" class="theme-toggle-button">
                    ${sunIcon}
                    ${moonIcon}
                </button>
                <button type="button" id="top-bar-messaging-button" aria-label="私信" class="messaging-button hidden">
                    ${messageIcon}
                    <span id="unread-messages-indicator" class="unread-badge hidden"></span>
                </button>
                <div id="top-bar-auth-buttons" class="auth-actions hidden">
                    <a href="/user/register" class="button secondary small">注册</a>
                    <a href="/user/login" class="button primary small">登录</a>
                </div>
                <div id="top-bar-user-info" class="user-info-dropdown hidden">
                    <button id="user-menu-button" class="user-menu-button">
                        ${userIcon}
                        <span class="username-text" id="top-bar-user-username"></span>
                    </button>
                    <div id="user-dropdown-menu" class="dropdown-menu hidden">
                        <div class="dropdown-user-email" id="top-bar-user-email"></div>
                        <hr class="dropdown-divider">
                        <a href="/user/profile" id="top-bar-account-link" class="dropdown-item">${personalInfoIcon}账户设置</a>
                        <a href="/user/admin" id="top-bar-admin-link" class="dropdown-item hidden">${adminIcon}管理员面板</a>
                        <a href="/user/help" class="dropdown-item">${helpIcon}帮助与API示例</a>
                        <button type="button" class="dropdown-item logout" id="top-bar-logout-button">安全登出</button>
                    </div>
                </div>
            </div>
        </header>
        <aside id="sidebar" class="sidebar">
            <nav class="sidebar-nav">
                <ul id="account-tabs">
                     <li><a href="/user/profile" class="sidebar-link">${personalInfoIcon}返回账户</a></li>
                </ul>
            </nav>
        </aside>
        <div id="sidebar-overlay" class="sidebar-overlay hidden"></div>
        <main id="main-content" class="main-content">
            <div class="container">
                <div id="message-area" class="message hidden" role="alert"></div>
                <div id="help-page-content" class="help-content api-usage-section">
                    <h3>OAuth&nbsp;验证流程</h3>
                    <h4>1. 获取访问令牌 (Access Token) 和 ID 令牌 (ID Token)</h4>
                    <p>在您的客户端应用完成 OAuth 授权码流程后，使用授权码向 <code>/oauth/token</code> 端点发起 POST 请求以交换令牌。</p>
                    <pre><code>curl -X POST "${OAUTH_ISSUER_URL(env, {url: 'https://example.com'})}/oauth/token" \\
    -H "Content-Type: application/x-www-form-urlencoded" \\
    -d "grant_type=authorization_code" \\
    -d "code=YOUR_AUTHORIZATION_CODE" \\
    -d "redirect_uri=YOUR_REGISTERED_REDIRECT_URI" \\
    -d "client_id=YOUR_CLIENT_ID" \\
    -d "client_secret=YOUR_CLIENT_SECRET"</code></pre>
                    <p>成功的响应将包含 <code>access_token</code>, <code>id_token</code> 等。</p>
                    <hr class="section-divider">
                    <h4>2. 使用访问令牌获取用户信息</h4>
                    <p>获得访问令牌后，向 <code>/oauth/userinfo</code> 端点请求用户信息。</p>
                    <pre><code>curl -X GET "${OAUTH_ISSUER_URL(env, {url: 'https://example.com'})}/oauth/userinfo" \\
    -H "Authorization: Bearer YOUR_ACCESS_TOKEN"</code></pre>
                    <p>响应内容取决于授予的权限范围 (scopes)。</p>
                </div>
            </div>
        </main>
    </div>
    <script src="${cdnBaseUrl}/js/main.js" defer></script>
    <script>
        (function() {
            const themeToggleButton = document.getElementById('theme-toggle-button');
            const themeToggleDarkIcon = document.getElementById('theme-toggle-dark-icon');
            const themeToggleLightIcon = document.getElementById('theme-toggle-light-icon');
            let isDarkMode = localStorage.getItem('theme') === 'dark' ||
                             (!localStorage.getItem('theme') && window.matchMedia('(prefers-color-scheme: dark)').matches);
            function applyTheme(dark) {
                document.body.classList.toggle('dark-mode', dark);
                if (themeToggleDarkIcon) themeToggleDarkIcon.style.display = dark ? 'block' : 'none';
                if (themeToggleLightIcon) themeToggleLightIcon.style.display = dark ? 'none' : 'block';
            }
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
        })();
    </script>
</body>
</html>`;
}
export function generateConsentScreenHtml(data) {
    const { clientName, requestedScopes, user, formAction, clientId, redirectUri, scope, state, nonce, responseType, issuerUrl: consentIssuerUrl, cdnBaseUrl: consentCdnBaseUrl, env = {} } = data;
    const finalCdnBaseUrl = consentCdnBaseUrl || env.CDN_BASE_URL || "https://cdn.qmwneb946.dpdns.org";
    const siteName = "用户中心授权";
    const scopesHtml = requestedScopes.map(s => `<li>${escapeHtml(s)}</li>`).join('');
    return `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>授权请求 - ${siteName}</title>
    <link rel="stylesheet" href="${finalCdnBaseUrl}/css/style.css">
    <style>
        body { display: flex; justify-content: center; align-items: center; min-height: 100vh; padding: 20px; background-color: var(--current-bg-color); color: var(--current-text-color); }
        .consent-container { background-color: var(--current-surface-color); padding: 30px 40px; border-radius: var(--border-radius); box-shadow: var(--box-shadow-md); max-width: 480px; width:100%; text-align: center; }
        .consent-container h2 { margin-top: 0; color: var(--current-heading-color); font-size: 1.8em; margin-bottom: 20px; }
        .consent-container p { margin-bottom: 15px; line-height: 1.6; font-size: 1.05em; }
        .client-name { font-weight: bold; color: var(--primary-color); }
        .user-identifier { font-weight: bold; }
        .scopes-list { list-style: inside disc; text-align: left; margin: 20px auto; padding-left: 25px; max-width: fit-content; }
        .scopes-list li { margin-bottom: 8px; }
        .consent-buttons { margin-top: 30px; display: flex; justify-content: space-between; gap: 15px; }
        .consent-buttons button { flex-grow: 1; }
    </style>
</head>
<body class="font-sans antialiased">
    <div class="consent-container">
        <h2>授权请求</h2>
        <p>应用 <strong class="client-name">${escapeHtml(clientName)}</strong> (${escapeHtml(clientId)})</p>
        <p>正在请求访问您 <strong class="user-identifier">(${escapeHtml(user.username || user.email)})</strong> 的以下信息：</p>
        <ul class="scopes-list">${scopesHtml}</ul>
        <p>您是否允许此应用访问？</p>
        <form method="POST" action="${escapeHtml(formAction)}">
            <input type="hidden" name="client_id" value="${escapeHtml(clientId)}">
            <input type="hidden" name="redirect_uri" value="${escapeHtml(redirectUri)}">
            <input type="hidden" name="scope" value="${escapeHtml(scope)}">
            <input type="hidden" name="state" value="${escapeHtml(state || '')}">
            <input type="hidden" name="nonce" value="${escapeHtml(nonce || '')}">
            <input type="hidden" name="response_type" value="${escapeHtml(responseType)}">
            <div class="consent-buttons">
                <button type="submit" name="decision" value="deny" class="button secondary">拒绝</button>
                <button type="submit" name="decision" value="allow" class="button primary">允许</button>
            </div>
        </form>
    </div>
    <script>
        function escapeHtml(unsafe) {
            if (typeof unsafe !== 'string') return '';
            return unsafe.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
        }
        if (localStorage.getItem('theme') === 'dark' || (!localStorage.getItem('theme') && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
            document.body.classList.add('dark-mode');
        }
    </script>
</body>
</html>`;
}
export function generateErrorPageHtml(data) {
    const { title, message, issuerUrl, cdnBaseUrl: dataCdnBaseUrl, env = {} } = data;
    const cdnBaseUrl = dataCdnBaseUrl || env.CDN_BASE_URL || "https://cdn.qmwneb946.dpdns.org";
    const siteName = "用户中心";
    const finalIssuerUrl = issuerUrl || OAUTH_ISSUER_URL(env, {url: 'https://example.com'});
    return `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>错误 - ${siteName}</title>
    <link rel="stylesheet" href="${cdnBaseUrl}/css/style.css">
    <style>
        body { display: flex; justify-content: center; align-items: center; min-height: 100vh; padding: 20px; background-color: var(--current-bg-color); color: var(--current-text-color); }
        .error-container { background-color: var(--current-surface-color); padding: 30px 40px; border-radius: var(--border-radius); box-shadow: var(--box-shadow-md); max-width: 450px; width: 100%; text-align: center;}
        .error-container h1 { color: var(--danger-color); margin-top: 0; font-size: 2em; margin-bottom: 15px;}
        .error-container p { font-size: 1.1em; margin-bottom: 25px; }
        .error-container a { color: var(--primary-color); text-decoration: none; font-weight: 500; }
        .error-container a:hover { text-decoration: underline; }
    </style>
</head>
<body class="font-sans antialiased">
    <div class="error-container">
        <h1>${escapeHtml(title)}</h1>
        <p>${escapeHtml(message)}</p>
        <p><a href="${escapeHtml(finalIssuerUrl || '/user/login')}">返回登录或首页</a></p>
    </div>
    <script>
        function escapeHtml(unsafe) {
            if (typeof unsafe !== 'string') return '';
            return unsafe.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
        }
        if (localStorage.getItem('theme') === 'dark' || (!localStorage.getItem('theme') && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
            document.body.classList.add('dark-mode');
        }
    </script>
</body>
</html>`;
}
function escapeHtml(unsafe) {
    if (typeof unsafe !== 'string') return '';
    return unsafe.replace(/&/g, "&amp;")
                 .replace(/</g, "&lt;")
                 .replace(/>/g, "&gt;")
                 .replace(/"/g, "&quot;")
                 .replace(/'/g, "&#039;");
}
const OAUTH_ISSUER_URL = (env, request) => {
    if (request && request.url) {
        try {
            const url = new URL(request.url);
            return `${url.protocol}//${url.hostname}`;
        } catch (e) {
        }
    }
    if (env && env.EXPECTED_ISSUER_URL) {
        return env.EXPECTED_ISSUER_URL;
    }
    const currentHost = (typeof window !== 'undefined' && window.location) ? window.location.origin : 'https://my.qmwneb946.dpdns.org';
    return currentHost;
};
