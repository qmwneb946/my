// 前端脚本 - “安全设置”选项卡相关逻辑
// Frontend Script - "Security Settings" Tab Logic

// DOM 元素引用 (在此模块的 DOMContentLoaded 中初始化)
let changePasswordFormContainer, changePasswordForm;
let twoFAInterfaceContainer, status2FA, btnDisable2FA, btnInitEnable2FA, setup2FASection;
let qrCodeDisplay, otpAuthUriTextDisplay, temp2FASecretInput, setup2FACodeInput;
let btnShowChangePasswordForm, btnShow2FAInterface;
let btnCompleteEnable2FA, btnCancel2FASetup;

/**
 * 初始化安全设置选项卡的状态。
 * 主要用于更新 2FA 相关的 UI 元素。
 * 当用户已登录且视图切换到账户设置时，由 main.js 中的 displayCorrectView 调用。
 * @param {object} userData 从 /api/me 获取的用户数据。
 */
function initializeSecuritySettings(userData) {
    // 确保 DOM 元素已获取
    status2FA = status2FA || document.getElementById('2fa-current-status');
    btnDisable2FA = btnDisable2FA || document.getElementById('btn-disable-2fa');
    btnInitEnable2FA = btnInitEnable2FA || document.getElementById('btn-init-enable-2fa');
    setup2FASection = setup2FASection || document.getElementById('2fa-setup-section');
    changePasswordFormContainer = changePasswordFormContainer || document.getElementById('change-password-form-container');
    twoFAInterfaceContainer = twoFAInterfaceContainer || document.getElementById('2fa-interface-container');


    if (userData && typeof userData.two_factor_enabled !== 'undefined') {
        update2FAStatusUI(userData.two_factor_enabled);
    }
    // 初始隐藏表单和设置区域
    if (changePasswordFormContainer) changePasswordFormContainer.classList.add('hidden');
    if (twoFAInterfaceContainer) twoFAInterfaceContainer.classList.add('hidden');
    if (setup2FASection) setup2FASection.classList.add('hidden'); // 确保2FA设置详情默认隐藏
}

/**
 * 更新 2FA 状态相关的 UI 元素。
 * @param {boolean} is2FAEnabled 2FA 是否已启用。
 */
function update2FAStatusUI(is2FAEnabled) {
    // 确保 DOM 元素已获取
    status2FA = status2FA || document.getElementById('2fa-current-status');
    btnDisable2FA = btnDisable2FA || document.getElementById('btn-disable-2fa');
    btnInitEnable2FA = btnInitEnable2FA || document.getElementById('btn-init-enable-2fa');
    setup2FASection = setup2FASection || document.getElementById('2fa-setup-section');


    if (!status2FA || !btnDisable2FA || !btnInitEnable2FA) {
        // console.warn("2FA UI elements not found for update.");
        return;
    }
    status2FA.textContent = is2FAEnabled ? "已启用" : "未启用";
    status2FA.style.color = is2FAEnabled ? 'var(--success-color)' : 'var(--danger-color)';
    btnDisable2FA.classList.toggle('hidden', !is2FAEnabled);
    btnInitEnable2FA.classList.toggle('hidden', is2FAEnabled);

    if (!is2FAEnabled) { // 如果2FA未启用，确保设置区域被隐藏和清理
        cancel2FASetup(); // 调用取消函数来重置设置表单
    }
}

/**
 * 处理修改密码表单提交。
 */
async function handleChangePasswordSubmit(event) {
    event.preventDefault();
    if (typeof window.clearMessages === 'function') window.clearMessages();

    const currentPasswordInput = document.getElementById('current-password');
    const newPasswordInput = document.getElementById('new-password');

    const currentPassword = currentPasswordInput.value;
    const newPassword = newPasswordInput.value;

    if (!currentPassword || !newPassword) {
        if (typeof window.showMessage === 'function') window.showMessage('当前密码和新密码均不能为空。', 'error');
        return;
    }
    if (newPassword.length < 6) {
        if (typeof window.showMessage === 'function') window.showMessage('新密码至少需要6个字符。', 'error');
        return;
    }

    if (typeof window.apiCall === 'function') {
        const { ok, data, status } = await window.apiCall('/api/change-password', 'POST', { currentPassword, newPassword });
        if (ok && data.success) {
            if (typeof window.showMessage === 'function') window.showMessage(data.message || '密码修改成功！所有旧会话已失效。', 'success');
            if (changePasswordForm) changePasswordForm.reset();
            if (changePasswordFormContainer) changePasswordFormContainer.classList.add('hidden');
        } else {
            if (typeof window.showMessage === 'function') window.showMessage(data.error || `密码修改失败 (${status})`, 'error');
        }
    }
}

/**
 * 显示或隐藏修改密码表单。
 */
function showChangePasswordForm() {
    if (typeof window.clearMessages === 'function') window.clearMessages();
    changePasswordFormContainer = changePasswordFormContainer || document.getElementById('change-password-form-container');
    twoFAInterfaceContainer = twoFAInterfaceContainer || document.getElementById('2fa-interface-container');
    changePasswordForm = changePasswordForm || document.getElementById('change-password-form');


    if (changePasswordFormContainer) {
        changePasswordFormContainer.classList.toggle('hidden');
        if (!changePasswordFormContainer.classList.contains('hidden') && changePasswordForm) {
            changePasswordForm.reset(); 
        }
    }
    if (twoFAInterfaceContainer) twoFAInterfaceContainer.classList.add('hidden'); 
}

/**
 * 显示或隐藏 2FA 设置界面。
 */
function show2FASetupInterface() {
    if (typeof window.clearMessages === 'function') window.clearMessages();
    twoFAInterfaceContainer = twoFAInterfaceContainer || document.getElementById('2fa-interface-container');
    changePasswordFormContainer = changePasswordFormContainer || document.getElementById('change-password-form-container');

    if (twoFAInterfaceContainer) {
        twoFAInterfaceContainer.classList.toggle('hidden');
        if (twoFAInterfaceContainer.classList.contains('hidden')) {
            cancel2FASetup(); 
        }
    }
    if (changePasswordFormContainer) changePasswordFormContainer.classList.add('hidden'); 
}


/**
 * 开始启用 2FA 的流程。
 */
async function initEnable2FA() {
    if (typeof window.clearMessages === 'function') window.clearMessages();
    qrCodeDisplay = qrCodeDisplay || document.getElementById('qrcode-display');
    otpAuthUriTextDisplay = otpAuthUriTextDisplay || document.getElementById('otpauth-uri-text-display');
    temp2FASecretInput = temp2FASecretInput || document.getElementById('2fa-temp-secret');
    setup2FACodeInput = setup2FACodeInput || document.getElementById('2fa-setup-code');
    setup2FASection = setup2FASection || document.getElementById('2fa-setup-section');
    btnInitEnable2FA = btnInitEnable2FA || document.getElementById('btn-init-enable-2fa');


    if (typeof window.apiCall === 'function') {
        const { ok, data, status } = await window.apiCall('/api/2fa/generate-secret');
        if (ok && data.success) {
            if (qrCodeDisplay) qrCodeDisplay.innerHTML = ''; 
            if (qrCodeDisplay && typeof QRCode !== 'undefined') {
                const isDark = document.body.classList.contains('dark-mode');
                new QRCode(qrCodeDisplay, {
                    text: data.otpauthUri,
                    width: 180, height: 180,
                    colorDark: isDark ? "#e2e8f0" : "#000000",
                    colorLight: isDark ? "#2d3748" : "#ffffff",
                    correctLevel: QRCode.CorrectLevel.H
                });
            }
            if (otpAuthUriTextDisplay) otpAuthUriTextDisplay.textContent = data.otpauthUri;
            if (temp2FASecretInput) temp2FASecretInput.value = data.secret;
            if (setup2FASection) setup2FASection.classList.remove('hidden');
            if (setup2FACodeInput) setup2FACodeInput.value = ''; 
            if (btnInitEnable2FA) btnInitEnable2FA.classList.add('hidden'); 
        } else {
            if (typeof window.showMessage === 'function') window.showMessage(data.error || `无法开始两步验证设置 (${status})`, 'error');
        }
    }
}

/**
 * 完成启用 2FA 的流程。
 */
async function completeEnable2FA() {
    if (typeof window.clearMessages === 'function') window.clearMessages();
    temp2FASecretInput = temp2FASecretInput || document.getElementById('2fa-temp-secret');
    setup2FACodeInput = setup2FACodeInput || document.getElementById('2fa-setup-code');

    const secret = temp2FASecretInput?.value;
    const totpCode = setup2FACodeInput?.value;

    if (!secret || !totpCode) {
        if (typeof window.showMessage === 'function') window.showMessage('请输入身份验证器生成的6位验证码。', 'error');
        return;
    }
    if (!/^\d{6}$/.test(totpCode)) {
        if (typeof window.showMessage === 'function') window.showMessage('验证码必须是6位数字。', 'error');
        return;
    }

    if (typeof window.apiCall === 'function') {
        const { ok, data, status } = await window.apiCall('/api/2fa/enable', 'POST', { secret, totpCode });
        if (ok && data.success) {
            if (typeof window.showMessage === 'function') window.showMessage(data.message || '两步验证已成功启用！', 'success');
            cancel2FASetup(); 
            if (typeof window.checkLoginStatus === 'function') await window.checkLoginStatus(); 
        } else {
            if (typeof window.showMessage === 'function') window.showMessage(data.error || `启用两步验证失败 (${status})。验证码可能不正确或密钥已过期。`, 'error');
            if (setup2FACodeInput) setup2FACodeInput.value = ''; 
        }
    }
}

/**
 * 取消 2FA 设置流程。
 */
function cancel2FASetup() {
    setup2FASection = setup2FASection || document.getElementById('2fa-setup-section');
    qrCodeDisplay = qrCodeDisplay || document.getElementById('qrcode-display');
    otpAuthUriTextDisplay = otpAuthUriTextDisplay || document.getElementById('otpauth-uri-text-display');
    temp2FASecretInput = temp2FASecretInput || document.getElementById('2fa-temp-secret');
    setup2FACodeInput = setup2FACodeInput || document.getElementById('2fa-setup-code');
    btnInitEnable2FA = btnInitEnable2FA || document.getElementById('btn-init-enable-2fa');
    status2FA = status2FA || document.getElementById('2fa-current-status');


    if (setup2FASection) setup2FASection.classList.add('hidden');
    if (temp2FASecretInput) temp2FASecretInput.value = '';
    if (setup2FACodeInput) setup2FACodeInput.value = '';
    if (qrCodeDisplay) qrCodeDisplay.innerHTML = '';
    if (otpAuthUriTextDisplay) otpAuthUriTextDisplay.textContent = '';

    const is2FACurrentlyEnabled = status2FA && status2FA.textContent === "已启用";
    if (btnInitEnable2FA && !is2FACurrentlyEnabled) {
        btnInitEnable2FA.classList.remove('hidden');
    }
}

/**
 * 禁用 2FA。
 */
async function disable2FA() {
    if (typeof window.clearMessages === 'function') window.clearMessages();
    if (!confirm("确定要禁用两步验证吗？这将降低您账户的安全性。")) return;

    if (typeof window.apiCall === 'function') {
        const { ok, data, status } = await window.apiCall('/api/2fa/disable', 'POST');
        if (ok && data.success) {
            if (typeof window.showMessage === 'function') window.showMessage(data.message || '两步验证已成功禁用。', 'success');
            if (typeof window.checkLoginStatus === 'function') await window.checkLoginStatus(); 
        } else {
            if (typeof window.showMessage === 'function') window.showMessage(data?.error || `禁用两步验证失败 (${status})`, 'error');
        }
    }
}


// DOMContentLoaded 后绑定事件
document.addEventListener('DOMContentLoaded', () => {
    changePasswordFormContainer = document.getElementById('change-password-form-container');
    changePasswordForm = document.getElementById('change-password-form');
    twoFAInterfaceContainer = document.getElementById('2fa-interface-container');
    status2FA = document.getElementById('2fa-current-status');
    btnDisable2FA = document.getElementById('btn-disable-2fa');
    btnInitEnable2FA = document.getElementById('btn-init-enable-2fa');
    setup2FASection = document.getElementById('2fa-setup-section');
    qrCodeDisplay = document.getElementById('qrcode-display');
    otpAuthUriTextDisplay = document.getElementById('otpauth-uri-text-display');
    temp2FASecretInput = document.getElementById('2fa-temp-secret');
    setup2FACodeInput = document.getElementById('2fa-setup-code');
    btnShowChangePasswordForm = document.getElementById('btn-show-change-password-form');
    btnShow2FAInterface = document.getElementById('btn-show-2fa-interface');
    btnCompleteEnable2FA = document.getElementById('btn-complete-enable-2fa');
    btnCancel2FASetup = document.getElementById('btn-cancel-2fa-setup');

    if (changePasswordForm) changePasswordForm.addEventListener('submit', handleChangePasswordSubmit);
    if (btnShowChangePasswordForm) btnShowChangePasswordForm.addEventListener('click', showChangePasswordForm);
    if (btnShow2FAInterface) btnShow2FAInterface.addEventListener('click', show2FASetupInterface);
    if (btnInitEnable2FA) btnInitEnable2FA.addEventListener('click', initEnable2FA);
    if (btnCompleteEnable2FA) btnCompleteEnable2FA.addEventListener('click', completeEnable2FA);
    if (btnCancel2FASetup) btnCancel2FASetup.addEventListener('click', cancel2FASetup);
    if (btnDisable2FA) btnDisable2FA.addEventListener('click', disable2FA);

    window.initializeSecuritySettings = initializeSecuritySettings;
    window.update2FAStatusUI = update2FAStatusUI; // 确保 main.js 可以调用
});
