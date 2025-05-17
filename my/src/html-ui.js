// html-ui.js
// 生成 HTML UI 的函数 / Function to generate HTML UI

/**
 * 生成主用户界面的 HTML。
 * @param {string} currentPath 当前请求的路径。
 * @param {object} env 环境变量，可能包含 CDN 基地址等。
 * @returns {string} HTML 字符串。
 */
export function generateHtmlUi(currentPath = '/', env = {}) {
    const showLogin = currentPath === '/' || currentPath === '/user/login';
    const showRegister = currentPath === '/user/register';
    const showAccount = currentPath === '/user/account';
    const authSectionVisible = showLogin || showRegister;

    const faviconDataUri = "data:image/jpeg;base64,/9j/4AAQSkZJRgABAQAAAQABAAD/4QAqRXhpZgAASUkqAAgAAAABADEBAgAHAAAAGgAAAAAAAABQaWNhc2EAAP/bAIQAAwICAwICAwMDAwQDAwQFCAUFBAQFCgcHBggMCgwNCwoLCw0OEhANDhEQCwsQFhARExQVFRUMDxcYFhQYEhQVEAEDBAQFBAYKBgUJFA4MDg8NFA0QDRQPERUPDxIVDQ0PEA8QFQ0ODw0NFQ0ODQ8NDRAQEA8NDQ0NDw8ODQ8NDQ0N/8AAEQgAIAAgAwERAAIRAQMRAf/EABkAAAMBAQEAAAAAAAAAAAAAAAUHCAYEA//EAC0QAAEDAgUCBQMFAAAAAAAAAAECAxEEBQAGEiExE0EIFCJR0WFx4QckgbHB/8QAGgEAAgMBAQAAAAAAAAAAAAAAAwYCBAUAAf/EACcRAAIBAgQFBQEAAAAAAAAAAAECAAMRBAUhQRJRcZHwMTKBodEU/9oADAMBAAIRAxEAPwCErU4VU3k6hI6Cok7ek++/3O/OGCmQRYwBQjWetYl21tqpxprrcV6gqCTuOJ7H09sFIK6bSJW8zlepM+kQnsI4GAtOEFOpG+wA4G2AkQgh6kbU0pJCVIPMg8YOgtOJjIyoly/0ybRWvldLrLrDSQJ6pSY/3n35GNBBxgKTIA2nJe8k0JpqllOpu6NOLQpsKBKoiDHIG47d8QZE1G8nwn1izqLY7TlepBKQSNxzjPZZ6BaWxU+AbM6WS8w2lTQjSA+hwkEHkiI7dsLa59h979o3NkbA2DC/z+CY24foBmHItTrrLG6lDDh/c9WDyIVHqT8Y06GbUKvseU6mTV6WrJpzHhgjP1a1W3Nm7uIVU16EBh6FJSFhM6TGkGfr9B2xof1lzeUnw6pt52iZvK6XzDxLa2zJ4VM/1is9QneBCoNpXVg8bOWssWNFttliuFEgDR0xeX9AHuANpwhVMoxb6cY7R5p5ngFsSh+oos7eJBjND1QqnpLkwp9W4duDroA9wDMfwcamFytqFuNgeglXFZzTrAimhHUmLw518o49VdKpXVSVNq8wAgHfkLaVP2+Mb6rYWizUcNrF7c6xyrqXVwRrJO6vxgkqa8p//9k=";
    const cdnBaseUrl = env.CDN_BASE_URL || "https://cdn.qmwneb946.dpdns.org";
    const exampleAccessToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL215LnFtd25lYjk0Ni5kcGRucy5vcmciLCJzdWIiOiJ0ZXN0QHRlc3QuY29tIiwiYXVkIjoiNGQ0NzdjZmItYjQwYi00NzhiLTg2M2MtMmU2MWZmMTNmMGQzIiwiZXhwIjoxNzQ3Mzk4MTA5LCJpYXQiOjE3NDczOTA5MDksImNsaWVudF9pZCI6IjRkNDc3Y2ZiLWI0MGItNDc4Yi04NjNjLTJlNjFmZjEzZjBkMyIsInNjb3BlIjoib3BlbmlkIHByb2ZpbGUgZW1haWwifQ.NqjOONMW-o5HzHVJGQqpjTFYdRSYTQSbIIcQnEgYGRU8dMPW2old7QlvGmnJtEktE2vhImJ82Fa4Nk34FnY2jhxKNunFBNcPYt8hP1u1VwGyNWR7GXJOFo1wI3EVw8DUsDI4wkMvBrntWwWfQ-t8_GWaCf6DNwhKt8jeAJ2vHhbx2IMbhSJq3EUfrbOUbrQlm4qvJUPBltOwTMPwxOo81jPgkWspjvn6mVWCDca2gALmn_1tFdlsCv-yaqFNULwRTYuxTXUhIyjBh6vhea4HQEXgnXYTbQUZn6Kgr4MDimeVzCP-xmqqrZeXO3tiLsricXTNlTSkhTthIsG-hy2pWg";


    return `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>用户中心</title>
    <link rel="icon" type="image/jpeg" href="${faviconDataUri}">
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
        .modal.active {
            opacity: 1; visibility: visible; transition: opacity 0.3s ease;
        }
        .modal-content {
            background-color: var(--surface-color); color: var(--text-color);
            padding: 25px 30px; border-radius: var(--border-radius);
            box-shadow: 0 5px 15px rgba(0,0,0,0.3); width: 90%; max-width: 500px;
            transform: translateY(-20px); transition: transform 0.3s ease;
        }
        .modal.active .modal-content {
            transform: translateY(0);
        }
        .modal-content h4 { margin-top: 0; text-align: left; font-size: 1.4em; color: var(--heading-color); }
        .modal-buttons { margin-top: 25px; text-align: right; }
        .modal-buttons button { margin-left: 10px; }
        .application-actions button { margin-right: 8px; }
        
        .api-usage-section pre {
            background-color: var(--otp-uri-bg-color);
            color: var(--text-color);
            padding: 15px;
            border-radius: var(--border-radius);
            overflow-x: auto;
            font-family: monospace;
            font-size: 0.9em;
            border: 1px solid var(--border-color);
            margin-bottom: 15px;
        }
        .api-usage-section h4 {
            font-size: 1.2em;
            color: var(--heading-color);
            margin-top: 25px;
            margin-bottom: 10px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 5px;
        }
        .api-usage-section p, .api-usage-section ul, .api-usage-section ol {
            font-size: 0.95em;
            line-height: 1.7;
            color: var(--text-color-muted);
        }
        .api-usage-section ul, .api-usage-section ol {
            margin-left: 20px;
            margin-bottom: 15px;
            padding-left: 20px;
        }
        .api-usage-section code.inline-code {
            background-color: color-mix(in srgb, var(--text-color) 10%, transparent);
            padding: 2px 5px;
            border-radius: 3px;
            font-family: monospace;
        }

        /* 私信界面样式 */
        .messaging-layout {
            display: flex;
            height: calc(100vh - 200px); /* 示例高度，根据实际情况调整 */
            border: 1px solid var(--border-color);
            border-radius: var(--border-radius);
        }
        .conversations-list {
            width: 30%;
            min-width: 200px;
            border-right: 1px solid var(--border-color);
            overflow-y: auto;
            padding: 0; margin:0; list-style-type: none;
        }
        .conversations-list li {
            padding: 15px;
            cursor: pointer;
            border-bottom: 1px solid var(--border-color);
            transition: background-color 0.2s ease;
        }
        .conversations-list li:last-child { border-bottom: none; }
        .conversations-list li:hover { background-color: color-mix(in srgb, var(--surface-color) 90%, var(--bg-color)); }
        .conversations-list li.active-conversation {
            background-color: var(--primary-color);
            color: white;
        }
        .conversations-list li.active-conversation .conversation-username,
        .conversations-list li.active-conversation .conversation-last-message,
        .conversations-list li.active-conversation .conversation-time,
        .conversations-list li.active-conversation .unread-badge {
             color: white !important; 
        }
        .conversation-username { font-weight: bold; display: block; margin-bottom: 4px; color: var(--heading-color); }
        .conversation-last-message { font-size: 0.9em; color: var(--text-color-muted); text-overflow: ellipsis; overflow: hidden; white-space: nowrap; display:block; }
        .conversation-time { font-size: 0.8em; color: var(--text-color-muted); float: right; }
        .unread-badge {
            background-color: var(--danger-color);
            color: white;
            border-radius: 50%;
            padding: 2px 6px;
            font-size: 0.75em;
            margin-left: 8px;
            min-width: 18px; text-align: center; display:inline-block;
        }

        .messages-area {
            flex-grow: 1;
            display: flex;
            flex-direction: column;
            padding: 0; 
        }
        .messages-list {
            flex-grow: 1;
            overflow-y: auto;
            padding: 20px;
            display: flex;
            flex-direction: column-reverse; /* 新消息在底部 */
        }
        .message-item {
            max-width: 70%;
            padding: 10px 15px;
            border-radius: 15px;
            margin-bottom: 10px;
            line-height: 1.4;
            word-wrap: break-word;
        }
        .message-item.sent {
            background-color: var(--primary-color);
            color: white;
            align-self: flex-end;
            border-bottom-right-radius: 5px;
        }
        .message-item.received {
            background-color: color-mix(in srgb, var(--surface-color) 85%, var(--bg-color));
            color: var(--text-color);
            align-self: flex-start;
            border-bottom-left-radius: 5px;
            border: 1px solid var(--border-color);
        }
        .message-sender { font-size: 0.8em; color: var(--text-color-muted); margin-bottom: 3px; display: block; }
        body.dark-mode .message-item.sent .message-sender { color: rgba(255,255,255,0.7); }
        body.dark-mode .message-item.received .message-sender { color: var(--text-color-muted); }

        .message-content { font-size: 0.95em; }
        .message-content p:first-child { margin-top: 0; } /* 移除Markdown转换后可能产生的额外<p>边距 */
        .message-content p:last-child { margin-bottom: 0; }
        .message-content ul, .message-content ol { margin: 5px 0 5px 20px; }
        .message-content pre { margin: 5px 0; font-size: 0.85em; }


        .message-time { font-size: 0.75em; color: var(--text-color-muted); margin-top: 5px; text-align: right; display: block; }
        body.dark-mode .message-item.sent .message-time { color: rgba(255,255,255,0.6); }


        .message-input-area {
            display: flex;
            padding: 15px;
            border-top: 1px solid var(--border-color);
            background-color: var(--surface-color); 
        }
        .message-input-area textarea {
            flex-grow: 1;
            padding: 10px;
            border: 1px solid var(--border-color);
            border-radius: var(--border-radius);
            resize: none; 
            margin-right: 10px;
            font-family: var(--font-family-sans-serif);
            font-size: 0.95rem;
            min-height: 40px; 
            max-height: 120px; 
            overflow-y: auto; 
        }
        .message-input-area button {
            padding: 10px 20px;
        }
        #new-conversation-area { margin-bottom: 15px; padding: 10px; border: 1px dashed var(--border-color); border-radius: var(--border-radius); }
        #new-conversation-area input[type="email"] { width: calc(100% - 100px); margin-right: 10px; }
        #new-conversation-area button { width: 90px; }

    </style>
</head>
<body>
    <div id="top-bar" class="top-bar">
        <div class="top-bar-left-controls">
            <button type="button" id="theme-toggle-button" aria-label="切换主题">
                <svg id="theme-toggle-dark-icon" class="h-5 w-5 hidden" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"></path></svg>
                <svg id="theme-toggle-light-icon" class="h-5 w-5 hidden" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M12 3v1m0 16v1m8.66-12.66l-.707.707M5.05 5.05l-.707.707M21 12h-1M4 12H3m15.66 8.66l-.707-.707M6.757 17.243l-.707-.707M12 6a6 6 0 100 12 6 6 0 000-12z"></path></svg>
            </button>
            <div class="user-greeting hidden" id="top-bar-user-info">
                 欢迎, <span class="username-text" id="top-bar-user-username"></span>
                (<span class="email-text" id="top-bar-user-email"></span>)
                <span id="unread-messages-indicator" class="unread-badge hidden" style="margin-left: 10px;"></span>
            </div>
        </div>
        <div id="top-bar-auth-buttons" class="hidden" style="display: flex; align-items: center;">
            <a href="/user/register" id="top-bar-register-button" class="button info small" style="margin-right: 10px;">注册</a>
            <a href="/user/login" id="top-bar-login-button" class="button success small">登录</a>
        </div>
        <button type="button" class="logout small hidden" id="top-bar-logout-button">安全登出</button>
    </div>

    <div class="container">
        <div id="message-area" class="message hidden" role="alert"></div>

        <div id="auth-section" class="auth-section ${authSectionVisible ? '' : 'hidden'}">
            <div id="login-form" class="${showLogin ? '' : 'hidden'}">
                <h2>用户登录</h2>
                <form id="login-form-el">
                    <div class="form-group"><label for="login-identifier">邮箱或用户名</label><input type="text" id="login-identifier" name="identifier" required autocomplete="username email" placeholder="请输入您的邮箱或用户名"></div>
                    <div class="form-group"><label for="login-password">密码</label><input type="password" id="login-password" name="password" required autocomplete="current-password" placeholder="请输入密码"></div>
                    <div id="login-2fa-section" class="form-group hidden"><label for="login-totp-code">两步验证码</label><input type="text" id="login-totp-code" name="totpCode" pattern="\\d{6}" maxlength="6" placeholder="请输入6位验证码"></div>
                    <div class="cf-turnstile" data-sitekey="0x4AAAAAABHKV0NoiFCSQFUk" data-callback="turnstileCallbackLogin"></div>
                    <button type="submit" class="full-width">登录</button>
                </form>
                <div class="toggle-link">还没有账户？ <a href="/user/register">立即注册</a></div>
            </div>
            <div id="register-form" class="${showRegister ? '' : 'hidden'}">
                <h2>新用户注册</h2>
                <form id="register-form-el">
                    <div class="form-group"><label for="register-username">用户名</label><input type="text" id="register-username" name="username" required minlength="3" maxlength="30" placeholder="3-30位字符，可包含字母、数字、_-"></div>
                    <div class="form-group"><label for="register-email">邮箱地址</label><input type="email" id="register-email" name="email" required autocomplete="email" placeholder="例如：user@example.com"></div>
                    <div class="form-group"><label for="register-phone">手机号码 (可选)</label><input type="tel" id="register-phone" name="phoneNumber" autocomplete="tel" placeholder="例如：+8613800138000"></div>
                    <div class="form-group"><label for="register-password">设置密码 (至少6位)</label><input type="password" id="register-password" name="password" required minlength="6" autocomplete="new-password" placeholder="请输入至少6位密码"></div>
                    <div class="form-group"><label for="register-confirm-password">确认密码</label><input type="password" id="register-confirm-password" name="confirmPassword" required minlength="6" autocomplete="new-password" placeholder="请再次输入密码"></div>
                    <div class="cf-turnstile" data-sitekey="0x4AAAAAABHKV0NoiFCSQFUk" data-callback="turnstileCallbackRegister"></div>
                    <button type="submit" class="full-width">创建账户</button>
                </form>
                <div class="toggle-link">已经有账户了？ <a href="/user/login">返回登录</a></div>
            </div>
        </div>

        <div id="logged-in-section" class="logged-in-section ${showAccount ? '' : 'hidden'}">
            <h2>账户设置</h2>
            <ul id="account-tabs" class="account-tabs">
                <li><span id="tab-personal-info" class="tab-entry selected" data-pane-id="tab-content-personal-info">个人信息</span></li>
                <li><span id="tab-security-settings" class="tab-entry" data-pane-id="tab-content-security-settings">安全设置</span></li>
                <li><span id="tab-api-keys" class="tab-entry" data-pane-id="tab-content-api-keys">API 密钥</span></li>
                <li><span id="tab-my-applications" class="tab-entry" data-pane-id="tab-content-my-applications">我的应用</span></li>
                <li><span id="tab-messaging" class="tab-entry" data-pane-id="tab-content-messaging">私信</span></li>
                <li><span id="tab-api-usage-examples" class="tab-entry" data-pane-id="tab-content-api-usage-examples">API 使用示例</span></li>
            </ul>

            <div id="tab-content-personal-info" class="tab-pane">
                <h3>个人信息修改</h3>
                <form id="update-profile-form">
                    <div class="form-group"><label for="profile-username">用户名</label><input type="text" id="profile-username" name="username" required minlength="3" maxlength="30" placeholder="3-30位字符，可包含字母、数字、_-"></div>
                    <div class="form-group"><label for="profile-phone">手机号码 (可选)</label><input type="tel" id="profile-phone" name="phoneNumber" placeholder="例如：+8613800138000"></div>
                    <div class="form-group"><label for="profile-email">邮箱地址 (不可修改)</label><input type="email" id="profile-email" name="email" readonly disabled></div>
                    <button type="submit" class="primary full-width">保存个人信息</button>
                </form>
            </div>

            <div id="tab-content-security-settings" class="tab-pane hidden">
                <h3>安全设置</h3>
                <div class="security-settings-area">
                    <div class="security-setting-item" style="margin-bottom: 25px;">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;"><span style="font-weight: 500; font-size: 1.1em;">修改密码</span><button type="button" id="btn-show-change-password-form" class="button secondary" style="padding: 8px 15px; font-size: 0.9em;">修改</button></div>
                        <div id="change-password-form-container" class="hidden" style="margin-top: 15px; padding: 20px; border: 1px solid var(--border-color); border-radius: var(--border-radius); background-color: color-mix(in srgb, var(--surface-color) 95%, var(--bg-color));">
                            <form id="change-password-form"> <div class="form-group"><label for="current-password">当前密码</label><input type="password" id="current-password" name="currentPassword" required autocomplete="current-password" placeholder="请输入您当前的密码"></div>
                                <div class="form-group"><label for="new-password">新密码 (至少6位)</label><input type="password" id="new-password" name="newPassword" required minlength="6" autocomplete="new-password" placeholder="请输入新的密码"></div>
                                <button type="submit" class="secondary full-width">确认修改密码</button>
                            </form>
                        </div>
                    </div>
                    <div class="security-setting-item">
                         <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;"><span style="font-weight: 500; font-size: 1.1em;">两步验证码 (2FA)</span><button type="button" id="btn-show-2fa-interface" class="button success" style="padding: 8px 15px; font-size: 0.9em;">管理</button></div>
                        <p style="font-size: 0.9em; color: var(--text-color-muted); margin-bottom: 5px;">两步验证码是类似于银行密码器的、每分钟变化的动态密码。</p>
                        <p style="font-size: 0.9em; color: var(--text-color-muted); margin-bottom: 15px;">使用两步验证码可以帮您双重保护账户安全，防止单一密码泄露导致风险。</p>
                        <div id="2fa-interface-container" class="hidden" style="margin-top: 15px; padding: 20px; border: 1px solid var(--border-color); border-radius: var(--border-radius); background-color: color-mix(in srgb, var(--surface-color) 95%, var(--bg-color));">
                            <div id="2fa-status-section"><p>当前状态: <span id="2fa-current-status" style="font-weight:bold;">未知</span></p><button type="button" id="btn-disable-2fa" class="danger hidden">禁用两步验证</button><button type="button" id="btn-init-enable-2fa" class="success hidden">启用两步验证</button></div>
                            <div id="2fa-setup-section" class="hidden" style="margin-top:20px;">
                                <h4 style="font-size: 1.1em; margin-bottom:10px; color: var(--heading-color);">设置两步验证</h4>
                                <p>1. 使用您的身份验证器应用 (如 Google Authenticator, Authy 等) 扫描下方的二维码或手动输入密钥。</p>
                                <div style="text-align: center; margin: 15px 0;"><div id="qrcode-display"></div></div>
                                <p style="margin-top: 15px;">密钥链接 (如果无法扫描二维码，可手动输入):</p><code id="otpauth-uri-text-display" class="otpauth-uri-text"></code>
                                <p style="margin-top:15px;">2. 在下方输入身份验证器应用生成的6位验证码以完成设置。</p><input type="hidden" id="2fa-temp-secret">
                                <div class="form-group" style="margin-top:10px;"><label for="2fa-setup-code">6位验证码</label><input type="text" id="2fa-setup-code" name="totpCode" pattern="\\d{6}" maxlength="6" placeholder="请输入验证码"></div>
                                <button type="button" id="btn-complete-enable-2fa" class="success" style="margin-right:10px;">验证并启用</button><button type="button" id="btn-cancel-2fa-setup" class="secondary">取消</button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <div id="tab-content-api-keys" class="tab-pane hidden">
                 <h3>API 密钥管理</h3>
                <div class="api-key-section" style="margin-bottom: 30px;">
                    <h4>创建 <a href="http://go.qmwneb946.dpdns.org/?LinkId=37" target="_blank" rel="noopener noreferrer" class="external-paste-link">云剪贴板</a> 的API 密钥</h4>
                    <div id="create-paste-api-key-form-container" style="margin-bottom: 20px; padding: 20px; border: 1px solid var(--border-color); border-radius: var(--border-radius); background-color: color-mix(in srgb, var(--surface-color) 97%, var(--bg-color));">
                        <form id="create-paste-api-key-form"> <p style="font-size: 0.9em; color: var(--text-color-muted); margin-bottom: 20px;">API 密钥名称将根据您的用户名自动生成，且仅拥有文本粘贴权限。</p>
                            <div class="cf-turnstile" data-sitekey="0x4AAAAAABHKV0NoiFCSQFUk" data-callback="turnstileCallbackPasteApi"></div>
                            <button type="submit" class="success full-width">创建云剪贴板 API 密钥</button>
                        </form>
                    </div>
                    <div id="newly-created-api-key-display" class="hidden api-key-display-inline" style="margin-top: 15px;">
                        <h5>新创建的云剪贴板 API 密钥：</h5>
                        <div class="api-key-value-container">
                            <input type="text" id="new-api-key-value" readonly title="新 API 密钥值">
                            <button type="button" class="button small secondary" onclick="copyToClipboard(document.getElementById('new-api-key-value').value, '云剪贴板 API 密钥')">复制</button>
                        </div>
                    </div>
                </div>
                <hr class="section-divider">
                <div class="api-key-section">
                    <h4><a href="http://go.qmwneb946.dpdns.org/?LinkId=17" target="_blank" rel="noopener noreferrer" class="external-paste-link">Cloud PC </a>密钥</h4>
                    <div id="cloud-pc-key-status-area" style="margin-bottom: 15px;">
                        <p>正在加载 Cloud PC 密钥状态...</p>
                    </div>
                    <div id="create-cloud-pc-key-form-container" class="hidden" style="margin-top: 10px; padding: 20px; border: 1px solid var(--border-color); border-radius: var(--border-radius); background-color: color-mix(in srgb, var(--surface-color) 97%, var(--bg-color));">
                        <form id="create-cloud-pc-key-form"> <p style="font-size: 0.9em; color: var(--text-color-muted); margin-bottom: 20px;">每位用户仅可创建一次 Cloud PC 密钥，创建后将获得 1 次使用次数。</p>
                            <div class="cf-turnstile" data-sitekey="0x4AAAAAABHKV0NoiFCSQFUk" data-callback="turnstileCallbackCloudPc"></div>
                            <button type="submit" class="success full-width">创建 Cloud PC 密钥</button>
                        </form>
                    </div>
                    <div id="existing-cloud-pc-key-display" class="hidden" style="margin-top: 15px;">
                        <h5>您的 Cloud PC 密钥：</h5>
                        <div class="api-key-value-container">
                            <input type="text" id="cloud-pc-api-key-value" readonly title="Cloud PC API 密钥值">
                            <button type="button" class="button small secondary" onclick="copyToClipboard(document.getElementById('cloud-pc-api-key-value').value, 'Cloud PC API 密钥')">复制</button>
                        </div>
                        <p>剩余使用次数: <strong id="cloud-pc-usage-count"></strong></p>
                    </div>
                </div>
            </div>

            <div id="tab-content-my-applications" class="tab-pane hidden">
                 <h3>我的 OAuth 应用</h3>
                <div id="register-oauth-client-form-container" style="background-color: color-mix(in srgb, var(--surface-color) 97%, var(--bg-color)); padding: 20px; border-radius: var(--border-radius); border: 1px solid var(--border-color); margin-bottom: 30px;">
                    <h4 style="font-size: 1.2em; color: var(--heading-color); margin-top: 0; margin-bottom: 20px; text-align: left;">注册新应用</h4>
                    <form id="register-oauth-client-form"> <div class="form-group">
                            <label for="oauth-client-name">应用名称</label>
                            <input type="text" id="oauth-client-name" name="clientName" required maxlength="50" placeholder="例如：我的博客评论系统" class="border rounded p-1 w-full">
                        </div>
                        <div class="form-group">
                            <label for="oauth-client-website">应用主页 (可选)</label>
                            <input type="url" id="oauth-client-website" name="clientWebsite" maxlength="200" placeholder="例如：https://myblog.com" class="border rounded p-1 w-full">
                        </div>
                        <div class="form-group">
                            <label for="oauth-client-description">应用描述 (可选)</label>
                            <input type="text" id="oauth-client-description" name="clientDescription" maxlength="200" placeholder="简要描述您的应用" class="border rounded p-1 w-full">
                        </div>
                        <div class="form-group">
                            <label for="oauth-client-redirect-uri">回调地址 (Redirect URI)</label>
                            <input type="url" id="oauth-client-redirect-uri" name="redirectUri" required maxlength="255" placeholder="例如：https://myblog.com/oauth/callback" class="border rounded p-1 w-full">
                            <p style="font-size: 0.8em; color: var(--text-color-muted); margin-top: 5px;">用户授权后，我们将重定向到此地址。必须是 HTTPS 地址。</p>
                        </div>
                        <div class="cf-turnstile" data-sitekey="0x4AAAAAABHKV0NoiFCSQFUk" data-callback="turnstileCallbackOauthClient"></div>
                        <button type="submit" class="button success full-width">注册应用</button>
                    </form>
                    <div id="new-oauth-client-credentials" class="hidden" style="margin-top: 20px;">
                        <h5 style="font-size: 1.1em; color: var(--primary-color); margin-bottom: 10px;">应用注册成功！</h5>
                        <p>请妥善保管您的应用凭据，特别是 <strong>客户端密钥 (Client Secret)</strong>，它将仅显示这一次。</p>
                        <div class="application-card" style="margin-top:10px;">
                            <p><strong>客户端 ID (Client ID):</strong> <code id="new-client-id-display"></code> <button type="button" class="button small secondary" style="padding: 3px 8px; font-size:0.8em; margin-left:5px;" onclick="copyToClipboard(document.getElementById('new-client-id-display').textContent, '客户端 ID')">复制</button></p>
                            <p><strong>客户端密钥 (Client Secret):</strong> <code id="new-client-secret-display"></code> <button type="button" class="button small secondary" style="padding: 3px 8px; font-size:0.8em; margin-left:5px;" onclick="copyToClipboard(document.getElementById('new-client-secret-display').textContent, '客户端密钥')">复制</button></p>
                        </div>
                        <div class="new-client-secret-warning">
                           <strong>重要提示:</strong> 客户端密钥非常敏感，请立即复制并安全存储。关闭此页面或刷新后，您将无法再次查看此密钥。
                        </div>
                    </div>
                </div>
                <hr class="section-divider">
                <h4 id="registered-oauth-clients-list-title" style="font-size: 1.2em; color: var(--heading-color); margin-top: 0; margin-bottom: 20px; text-align: left;">已注册的应用</h4>
                <div id="registered-oauth-clients-list">
                    <p>正在加载应用列表...</p>
                </div>
            </div>

            <div id="tab-content-messaging" class="tab-pane hidden">
                <h3>私信</h3>
                <div id="new-conversation-area">
                    <label for="new-conversation-email">与用户开始新对话 (输入邮箱):</label>
                    <div style="display: flex;">
                        <input type="email" id="new-conversation-email" placeholder="对方邮箱地址">
                        <button type="button" id="btn-start-new-conversation" class="button success small">开始对话</button>
                    </div>
                </div>
                <div class="messaging-layout">
                    <ul id="conversations-list" class="conversations-list">
                        <p style="padding:15px; text-align:center; color: var(--text-color-muted);">正在加载对话...</p>
                    </ul>
                    <div id="messages-area" class="messages-area">
                        <div id="messages-list" class="messages-list">
                            <p style="text-align:center; color: var(--text-color-muted); margin-top:auto; margin-bottom:auto;">请选择一个对话以查看消息。</p>
                            </div>
                        <div id="message-input-area" class="message-input-area hidden">
                            <textarea id="message-input" placeholder="输入消息..." rows="3"></textarea>
                            <button type="button" id="btn-send-message" class="button">发送</button>
                        </div>
                    </div>
                </div>
            </div>

            <div id="tab-content-api-usage-examples" class="tab-pane hidden api-usage-section">
                <h3>API 使用示例</h3>
                <h4>1. 获取访问令牌 (Access Token) 和 ID 令牌 (ID Token)</h4>
                <p>在您的客户端应用完成 OAuth 授权码流程 (Authorization Code Flow) 的第一步 (将用户重定向到 IdP 的 <code>/oauth/authorize</code> 端点并获取到授权码 <code>code</code>) 之后，您需要使用该授权码向 IdP 的 <code>/oauth/token</code> 端点发起 POST 请求以交换令牌。</p>
                <p>以下是使用 <code class="inline-code">curl</code> 命令的示例 (请将占位符替换为您的实际值)：</p>
                <pre><code>curl -X POST "https://my.qmwneb946.dpdns.org/oauth/token" \\
-H "Content-Type: application/x-www-form-urlencoded" \\
-d "grant_type=authorization_code" \\
-d "code=YOUR_AUTHORIZATION_CODE" \\
-d "redirect_uri=YOUR_REGISTERED_REDIRECT_URI" \\
-d "client_id=YOUR_CLIENT_ID" \\
-d "client_secret=YOUR_CLIENT_SECRET"</code></pre>
                <p><strong>参数说明:</strong></p>
                <ul>
                    <li><code class="inline-code">YOUR_AUTHORIZATION_CODE</code>: 从 <code>/oauth/authorize</code> 重定向后获取到的授权码。</li>
                    <li><code class="inline-code">YOUR_REGISTERED_REDIRECT_URI</code>: 您在注册此客户端应用时设置的回调地址 (必须与获取授权码时使用的完全一致，并进行 URL 编码)。</li>
                    <li><code class="inline-code">YOUR_CLIENT_ID</code>: 您注册的 OAuth 应用的客户端 ID。</li>
                    <li><code class="inline-code">YOUR_CLIENT_SECRET</code>: 您注册的 OAuth 应用的客户端密钥。</li>
                </ul>
                <p>成功的响应将是一个 JSON 对象，包含 <code class="inline-code">access_token</code>, <code class="inline-code">id_token</code>, <code class="inline-code">token_type</code>, 和 <code class="inline-code">expires_in</code>。</p>
                <hr class="section-divider">
                <h4>2. 使用访问令牌获取用户信息</h4>
                <p>一旦您获得了访问令牌，就可以用它来向 IdP 的 <code>/oauth/userinfo</code> 端点请求受保护的用户信息。访问令牌需要在 HTTP 请求的 <code class="inline-code">Authorization</code> 头部中以 <code class="inline-code">Bearer</code> 方案提供。</p>
                <p>以下是使用 <code class="inline-code">curl</code> 命令的示例 (请将 <code class="inline-code">YOUR_ACCESS_TOKEN</code> 替换为您实际获取到的访问令牌)：</p>
                <pre><code>curl -X GET "https://my.qmwneb946.dpdns.org/oauth/userinfo" \\
-H "Authorization: Bearer ${exampleAccessToken}"</code></pre>
                <p><strong>注意:</strong> 上述命令中的 <code class="inline-code">Bearer</code> 后面是一个示例访问令牌。在实际使用中，您需要替换为您从 <code>/oauth/token</code> 端点获取到的真实访问令牌。</p>
                <p>成功的响应将是一个包含用户信息的 JSON 对象，其内容取决于访问令牌被授予的权限范围 (scopes)。例如，如果请求了 <code class="inline-code">openid profile email</code> 范围，可能会返回用户的 ID (<code class="inline-code">sub</code>), 名称, 邮箱等信息。</p>
                <h4>工作流程概述:</h4>
                <ol>
                    <li>用户通过您的客户端应用程序发起登录。</li>
                    <li>客户端应用程序将用户重定向到 IdP 的 <code>/oauth/authorize</code> 端点 (携带 client_id, redirect_uri, scope, state, nonce)。</li>
                    <li>用户在 IdP 上登录并同意授权。</li>
                    <li>IdP 将用户重定向回客户端的回调地址 (redirect_uri)，并附带授权码 (code) 和 state。</li>
                    <li>客户端应用程序的后端使用此授权码、客户端 ID 和客户端密钥向 IdP 的 <code>/oauth/token</code> 端点请求令牌。</li>
                    <li>IdP 验证通过后，返回访问令牌和 ID 令牌。</li>
                    <li>客户端应用程序使用访问令牌向 IdP 的 <code>/oauth/userinfo</code> 端点请求用户信息。</li>
                </ol>
            </div>
        </div>
    </div>

    <div id="edit-oauth-client-modal" class="modal hidden">
        <div class="modal-content">
            <h4 id="edit-oauth-client-modal-title">编辑应用信息</h4>
            <form id="edit-oauth-client-form">
                <input type="hidden" id="edit-client-id" name="clientId">
                <div class="form-group">
                    <label for="edit-oauth-client-name">应用名称</label>
                    <input type="text" id="edit-oauth-client-name" name="clientName" required maxlength="50" class="border rounded p-1 w-full">
                </div>
                <div class="form-group">
                    <label for="edit-oauth-client-website">应用主页 (可选)</label>
                    <input type="url" id="edit-oauth-client-website" name="clientWebsite" maxlength="200" class="border rounded p-1 w-full">
                </div>
                <div class="form-group">
                    <label for="edit-oauth-client-description">应用描述 (可选)</label>
                    <input type="text" id="edit-oauth-client-description" name="clientDescription" maxlength="200" class="border rounded p-1 w-full">
                </div>
                <div class="form-group">
                    <label for="edit-oauth-client-redirect-uri">回调地址 (Redirect URI)</label>
                    <input type="url" id="edit-oauth-client-redirect-uri" name="redirectUri" required maxlength="255" class="border rounded p-1 w-full">
                    <p style="font-size: 0.8em; color: var(--text-color-muted); margin-top: 5px;">必须是 HTTPS 地址。</p>
                </div>
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
    <script src="${cdnBaseUrl}/js/ui-messaging.js" defer></script> </body>
</html>`;
}

/**
 * 生成 OAuth 同意屏幕的 HTML。
 * @param {object} data - 包含 clientName, requestedScopes, user, formAction, clientId, redirectUri, scope, state, nonce, responseType, issuerUrl, cdnBaseUrl。
 * @returns {string} HTML 字符串。
 */
export function generateConsentScreenHtml(data) {
    const { clientName, requestedScopes, user, formAction, clientId, redirectUri, scope, state, nonce, responseType, issuerUrl, cdnBaseUrl } = data;
    const finalCdnBaseUrl = cdnBaseUrl || "https://cdn.qmwneb946.dpdns.org";
    const scopesHtml = requestedScopes.map(s => `<li>${escapeHtml(s)}</li>`).join('');

    return `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>授权请求 - 用户中心</title>
    <link rel="stylesheet" href="${finalCdnBaseUrl}/css/style.css">
    <style>
        body { display: flex; justify-content: center; align-items: center; min-height: 100vh; background-color: var(--bg-color, #e0e6e8); color: var(--text-color, #333); font-family: var(--font-family-sans-serif, sans-serif); margin: 20px;}
        .consent-container { background-color: var(--surface-color, #fff); padding: 20px 30px; border-radius: var(--border-radius, 0.375rem); box-shadow: var(--box-shadow, 0 0.25rem 0.75rem rgba(0,0,0,0.05)); max-width: 450px; width:100%; text-align: center; }
        .consent-container h2 { margin-top: 0; color: var(--heading-color, #2c3e50); }
        .consent-container p { margin-bottom: 15px; line-height: 1.6; }
        .consent-container ul { list-style: inside disc; text-align: left; margin-bottom: 20px; padding-left: 20px; }
        .consent-buttons button { margin: 5px; padding: 10px 15px; }
        strong { color: var(--primary-color, #1abc9c); }
        button, .button { background-color: var(--primary-color, #1abc9c); color: white; padding: 12px 20px; border: none; border-radius: var(--border-radius, 0.375rem); cursor: pointer; font-size: 1rem; font-weight: 500; transition: background-color 0.2s ease, box-shadow 0.2s ease; box-shadow: 0 2px 4px rgba(0,0,0,0.1); text-decoration: none; display: inline-block; text-align:center; }
        button:hover, .button:hover { background-color: var(--primary-color-dark, #16a085); box-shadow: 0 4px 8px rgba(0,0,0,0.15); }
        button.secondary, .button.secondary { background-color: var(--secondary-color, #95a5a6); }
        button.secondary:hover, .button.secondary:hover { background-color: color-mix(in srgb, var(--secondary-color, #95a5a6) 85%, black); }
    </style>
</head>
<body>
    <div class="consent-container">
        <h2>授权请求</h2>
        <p>应用 <strong>${escapeHtml(clientName)}</strong> (${escapeHtml(clientId)}) 正在请求访问您的以下信息：</p>
        <ul>${scopesHtml}</ul>
        <p>您 (${escapeHtml(user.username || user.email)}) 是否允许此应用访问？</p>
        <form method="POST" action="${escapeHtml(formAction)}">
            <input type="hidden" name="client_id" value="${escapeHtml(clientId)}">
            <input type="hidden" name="redirect_uri" value="${escapeHtml(redirectUri)}">
            <input type="hidden" name="scope" value="${escapeHtml(scope)}">
            <input type="hidden" name="state" value="${escapeHtml(state || '')}">
            <input type="hidden" name="nonce" value="${escapeHtml(nonce || '')}">
            <input type="hidden" name="response_type" value="${escapeHtml(responseType)}">
            <div class="consent-buttons">
                <button type="submit" name="decision" value="deny" class="button secondary">拒绝</button>
                <button type="submit" name="decision" value="allow" class="button">允许</button>
            </div>
        </form>
    </div>
    <script>
        function escapeHtml(unsafe) { 
            if (typeof unsafe !== 'string') return '';
            return unsafe.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
        }
        if (localStorage.getItem('theme') === 'dark' || (localStorage.getItem('theme') === null && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
            document.body.classList.add('dark-mode');
        }
    </script>
</body>
</html>`;
}

/**
 * 生成一个简单的 HTML 错误页面。
 * @param {object} data - 包含 title, message, issuerUrl, 和 cdnBaseUrl (或 env 对象).
 * @returns {string} HTML 字符串。
 */
export function generateErrorPageHtml(data) {
    const { title, message, issuerUrl, cdnBaseUrl: dataCdnBaseUrl, env = {} } = data;
    const cdnBaseUrl = dataCdnBaseUrl || env.CDN_BASE_URL || "https://cdn.qmwneb946.dpdns.org";
    return `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>错误 - 用户中心</title>
    <link rel="stylesheet" href="${cdnBaseUrl}/css/style.css">
    <style>
        body { display: flex; justify-content: center; align-items: center; min-height: 100vh; background-color: var(--bg-color, #f3f4f6); color: var(--text-color, #1f2937); font-family: var(--font-family-sans-serif, sans-serif); text-align: center; margin: 20px;}
        .error-container { background-color: var(--surface-color, white); padding: 20px 30px; border-radius: var(--border-radius, 8px); box-shadow: var(--box-shadow, 0 4px 6px rgba(0,0,0,0.1)); max-width: 400px; width: 100%;}
        .error-container h1 { color: var(--danger-color, #ef4444); margin-top: 0;}
        .error-container a { color: var(--primary-color, #1abc9c); }
    </style>
</head>
<body>
    <div class="error-container">
        <h1>${escapeHtml(title)}</h1>
        <p>${escapeHtml(message)}</p>
        <p><a href="${escapeHtml(issuerUrl || '/')}">返回首页或授权流程</a></p>
    </div>
    <script>
        function escapeHtml(unsafe) {
            if (typeof unsafe !== 'string') return '';
            return unsafe.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
        }
        if (localStorage.getItem('theme') === 'dark' || (localStorage.getItem('theme') === null && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
            document.body.classList.add('dark-mode');
        }
    </script>
</body>
</html>`;
}

// 简单的 HTML 转义函数，防止 XSS
function escapeHtml(unsafe) {
    if (typeof unsafe !== 'string') return '';
    return unsafe.replace(/&/g, "&amp;")
                 .replace(/</g, "&lt;")
                 .replace(/>/g, "&gt;")
                 .replace(/"/g, "&quot;")
                 .replace(/'/g, "&#039;");
}
