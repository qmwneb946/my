let securitySettingsList, changePasswordPanel, twoFaPanel;
let changePasswordForm;
let status2FA, btnDisable2FA, btnInitEnable2FA, setup2FASection;
let qrCodeDisplay, otpAuthUriTextDisplay, temp2FASecretInput, setup2FACodeInput;
let btnCompleteEnable2FA, btnCancel2FASetup;
let twoFaEntryStatusElement; 

function handleSecuritySettingEntryClick(event) {
    const entry = event.currentTarget; 
    const targetId = entry.dataset.target;
    const targetPanel = document.getElementById(targetId);
    const arrow = entry.querySelector('.entry-arrow');

    if (targetPanel) {
        targetPanel.classList.toggle('hidden'); 
        entry.classList.toggle('open', !targetPanel.classList.contains('hidden')); 

        if (arrow) {
            arrow.textContent = targetPanel.classList.contains('hidden') ? '▶' : '▼';
        }
    } else {
    }
}


function initializeSecuritySettings(userData) {
    securitySettingsList = document.querySelector('#tab-content-security-settings .security-settings-list');
    changePasswordPanel = document.getElementById('change-password-content-panel');
    twoFaPanel = document.getElementById('2fa-content-panel');
    twoFaEntryStatusElement = document.getElementById('2fa-entry-status');

    changePasswordForm = document.getElementById('change-password-form');
    status2FA = document.getElementById('2fa-current-status'); 
    btnDisable2FA = document.getElementById('btn-disable-2fa');
    btnInitEnable2FA = document.getElementById('btn-init-enable-2fa');
    setup2FASection = document.getElementById('2fa-setup-section');
    qrCodeDisplay = document.getElementById('qrcode-display');
    otpAuthUriTextDisplay = document.getElementById('otpauth-uri-text-display');
    temp2FASecretInput = document.getElementById('2fa-temp-secret');
    setup2FACodeInput = document.getElementById('2fa-setup-code');
    btnCompleteEnable2FA = document.getElementById('btn-complete-enable-2fa');
    btnCancel2FASetup = document.getElementById('btn-cancel-2fa-setup');

    if (securitySettingsList) {
        const entries = securitySettingsList.querySelectorAll('.setting-entry');
        entries.forEach(entry => {
            entry.removeEventListener('click', handleSecuritySettingEntryClick);
            entry.addEventListener('click', handleSecuritySettingEntryClick);

            const arrow = entry.querySelector('.entry-arrow');
            const targetId = entry.dataset.target;
            const targetPanel = document.getElementById(targetId);

            if (targetPanel && arrow) {
                arrow.textContent = targetPanel.classList.contains('hidden') ? '▶' : '▼';
                entry.classList.toggle('open', !targetPanel.classList.contains('hidden'));
            } else if (arrow) {
                arrow.textContent = '▶';
                entry.classList.remove('open');
            }
        });
    } else {
    }

    if (userData && typeof userData.two_factor_enabled !== 'undefined') {
        update2FAStatusUI(userData.two_factor_enabled);
    }

    if (setup2FASection && !btnInitEnable2FA.classList.contains('hidden')) { 
         setup2FASection.classList.add('hidden');
    }
}

function update2FAStatusUI(is2FAEnabled) {
    status2FA = status2FA || document.getElementById('2fa-current-status');
    btnDisable2FA = btnDisable2FA || document.getElementById('btn-disable-2fa');
    btnInitEnable2FA = btnInitEnable2FA || document.getElementById('btn-init-enable-2fa');
    setup2FASection = setup2FASection || document.getElementById('2fa-setup-section');
    twoFaEntryStatusElement = twoFaEntryStatusElement || document.getElementById('2fa-entry-status');

    if (!status2FA || !btnDisable2FA || !btnInitEnable2FA || !twoFaEntryStatusElement) {
        return;
    }
    const statusText = is2FAEnabled ? "已启用" : "未启用";
    status2FA.textContent = statusText;
    status2FA.style.color = is2FAEnabled ? 'var(--success-color)' : 'var(--danger-color)';
    
    twoFaEntryStatusElement.textContent = `(${statusText})`;
    twoFaEntryStatusElement.style.color = is2FAEnabled ? 'var(--success-color)' : 'var(--current-text-muted-color)';


    btnDisable2FA.classList.toggle('hidden', !is2FAEnabled);
    btnInitEnable2FA.classList.toggle('hidden', is2FAEnabled);

    if (!is2FAEnabled && setup2FASection && !setup2FASection.classList.contains('hidden')) {
        cancel2FASetup(); 
    }
}

async function handleChangePasswordSubmit(event) {
    event.preventDefault();
    if (typeof window.clearMessages === 'function') window.clearMessages();

    const currentPasswordInput = document.getElementById('current-password');
    const newPasswordInput = document.getElementById('new-password');

    if (!currentPasswordInput || !newPasswordInput) {
        if (typeof window.showMessage === 'function') window.showMessage('页面元素加载不完整，请刷新重试。', 'error');
        return;
    }

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
        } else {
            if (typeof window.showMessage === 'function') window.showMessage(data.error || `密码修改失败 (${status})`, 'error');
        }
    }
}

async function initEnable2FA() {
    if (typeof window.clearMessages === 'function') window.clearMessages();
    qrCodeDisplay = qrCodeDisplay || document.getElementById('qrcode-display');
    otpAuthUriTextDisplay = otpAuthUriTextDisplay || document.getElementById('otpauth-uri-text-display');
    temp2FASecretInput = temp2FASecretInput || document.getElementById('2fa-temp-secret');
    setup2FACodeInput = setup2FACodeInput || document.getElementById('2fa-setup-code');
    setup2FASection = setup2FASection || document.getElementById('2fa-setup-section');
    btnInitEnable2FA = btnInitEnable2FA || document.getElementById('btn-init-enable-2fa');

    if (!qrCodeDisplay || !otpAuthUriTextDisplay || !temp2FASecretInput || !setup2FACodeInput || !setup2FASection || !btnInitEnable2FA) {
        if (typeof window.showMessage === 'function') window.showMessage('页面元素加载不完整，无法开始2FA设置。', 'error');
        return;
    }

    if (typeof window.apiCall === 'function') {
        const { ok, data, status } = await window.apiCall('/api/2fa/generate-secret');
        if (ok && data.success) {
            qrCodeDisplay.innerHTML = ''; 
            if (typeof QRCode !== 'undefined') { 
                const isDark = document.body.classList.contains('dark-mode');
                new QRCode(qrCodeDisplay, {
                    text: data.otpauthUri,
                    width: 180, height: 180,
                    colorDark: isDark ? "#e2e8f0" : "#000000",
                    colorLight: "#ffffff", 
                    correctLevel: QRCode.CorrectLevel.H
                });
            } else {
                qrCodeDisplay.textContent = "QR Code library not loaded.";
            }
            otpAuthUriTextDisplay.textContent = data.otpauthUri;
            temp2FASecretInput.value = data.secret;
            setup2FASection.classList.remove('hidden');
            setup2FACodeInput.value = ''; 
            btnInitEnable2FA.classList.add('hidden'); 
        } else {
            if (typeof window.showMessage === 'function') window.showMessage(data.error || `无法开始两步验证设置 (${status})`, 'error');
        }
    }
}

async function completeEnable2FA() {
    if (typeof window.clearMessages === 'function') window.clearMessages();
    temp2FASecretInput = temp2FASecretInput || document.getElementById('2fa-temp-secret');
    setup2FACodeInput = setup2FACodeInput || document.getElementById('2fa-setup-code');

    if (!temp2FASecretInput || !setup2FACodeInput) {
        if (typeof window.showMessage === 'function') window.showMessage('页面元素加载不完整，无法完成2FA设置。', 'error');
        return;
    }

    const secret = temp2FASecretInput.value;
    const totpCode = setup2FACodeInput.value;

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
            setup2FACodeInput.value = ''; 
        }
    }
}

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

document.addEventListener('DOMContentLoaded', () => {
    changePasswordForm = document.getElementById('change-password-form');
    if (changePasswordForm) changePasswordForm.addEventListener('submit', handleChangePasswordSubmit);

    btnInitEnable2FA = document.getElementById('btn-init-enable-2fa');
    if (btnInitEnable2FA) btnInitEnable2FA.addEventListener('click', initEnable2FA);

    btnCompleteEnable2FA = document.getElementById('btn-complete-enable-2fa');
    if (btnCompleteEnable2FA) btnCompleteEnable2FA.addEventListener('click', completeEnable2FA);

    btnCancel2FASetup = document.getElementById('btn-cancel-2fa-setup');
    if (btnCancel2FASetup) btnCancel2FASetup.addEventListener('click', cancel2FASetup);

    btnDisable2FA = document.getElementById('btn-disable-2fa');
    if (btnDisable2FA) btnDisable2FA.addEventListener('click', disable2FA);

    window.initializeSecuritySettings = initializeSecuritySettings;
    window.update2FAStatusUI = update2FAStatusUI;
});
