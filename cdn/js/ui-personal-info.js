// 前端脚本 - “个人信息”选项卡相关逻辑
// Frontend Script - "Personal Info" Tab Logic

// DOM 元素引用 (在此模块的 DOMContentLoaded 中初始化)
let profileUsernameInput, profilePhoneInput, profileEmailInput;
let updateProfileForm;

/**
 * 初始化个人信息表单的函数。
 * 当用户已登录且视图切换到账户设置时，由 main.js 中的 displayCorrectView 调用。
 * @param {object} userData 从 /api/me 获取的用户数据。
 */
function initializePersonalInfoForm(userData) {
    // 确保 DOM 元素已获取，如果尚未获取
    profileUsernameInput = profileUsernameInput || document.getElementById('profile-username');
    profilePhoneInput = profilePhoneInput || document.getElementById('profile-phone');
    profileEmailInput = profileEmailInput || document.getElementById('profile-email');

    if (profileUsernameInput) profileUsernameInput.value = userData.username || '';
    if (profilePhoneInput) profilePhoneInput.value = userData.phone_number || '';
    if (profileEmailInput) profileEmailInput.value = userData.email || ''; // 邮箱通常不可修改
}

/**
 * 处理个人信息更新表单提交的函数。
 */
async function handleUpdateProfileSubmit(event) {
    event.preventDefault(); // 阻止表单的默认提交行为
    if (typeof window.clearMessages === 'function') window.clearMessages(); // 使用 main.js 中的全局函数

    // 再次获取元素，以防在 initializePersonalInfoForm时尚未完全可用
    const currentProfileUsernameInput = document.getElementById('profile-username');
    const currentProfilePhoneInput = document.getElementById('profile-phone');

    const username = currentProfileUsernameInput.value;
    const phoneNumber = currentProfilePhoneInput.value;

    // 前端基本验证
    if (!username || username.trim() === '') {
        if (typeof window.showMessage === 'function') window.showMessage('用户名不能为空。', 'error');
        return;
    }
    if (username.length < 3 || username.length > 30 || !/^[a-zA-Z0-9_-]+$/.test(username)) {
        if (typeof window.showMessage === 'function') window.showMessage('用户名必须为3-30位，可包含字母、数字、下划线和连字符', 'error');
        return;
    }
    if (phoneNumber && phoneNumber.trim() !== '' && !/^\+?[0-9\s-]{7,20}$/.test(phoneNumber)) {
        if (typeof window.showMessage === 'function') window.showMessage('手机号码格式无效', 'error');
        return;
    }

    const requestBody = {
        username: username.trim(),
        phoneNumber: phoneNumber.trim() === '' ? null : phoneNumber.trim() // 如果为空则发送 null
    };

    if (typeof window.apiCall === 'function') {
        const { ok, data, status } = await window.apiCall('/api/update-profile', 'POST', requestBody);
        if (ok && data.success) {
            if (typeof window.showMessage === 'function') window.showMessage(data.message || '个人信息更新成功！', 'success');
            // 更新成功后，可能需要重新获取用户信息或更新顶部栏显示
            if (typeof window.checkLoginStatus === 'function') await window.checkLoginStatus(); // 重新检查登录状态以更新UI
        } else {
            if (typeof window.showMessage === 'function') window.showMessage(data.error || ('更新失败 (' + status + ')'), 'error');
        }
    } else {
        console.error("apiCall function is not defined. Make sure main.js is loaded and apiCall is globally available.");
        if (typeof window.showMessage === 'function') window.showMessage('发生通讯错误，请重试。', 'error');
    }
}

// DOMContentLoaded 后绑定事件
document.addEventListener('DOMContentLoaded', () => {
    // 初始化 DOM 元素引用
    profileUsernameInput = document.getElementById('profile-username');
    profilePhoneInput = document.getElementById('profile-phone');
    profileEmailInput = document.getElementById('profile-email');
    updateProfileForm = document.getElementById('update-profile-form');

    if (updateProfileForm) {
        updateProfileForm.addEventListener('submit', handleUpdateProfileSubmit);
    }

    // 将 initializePersonalInfoForm 挂载到 window，以便 main.js 可以调用
    // 这是因为 main.js 中的 displayCorrectView 需要在 userData 可用时调用它
    window.initializePersonalInfoForm = initializePersonalInfoForm;
});
