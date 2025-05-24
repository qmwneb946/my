let profileUsernameInput, profilePhoneInput, profileEmailInput;
let updateProfileForm;

function initializePersonalInfoForm(userData) {
    profileUsernameInput = profileUsernameInput || document.getElementById('profile-username');
    profilePhoneInput = profilePhoneInput || document.getElementById('profile-phone');
    profileEmailInput = profileEmailInput || document.getElementById('profile-email');

    if (profileUsernameInput) profileUsernameInput.value = userData.username || '';
    if (profilePhoneInput) profilePhoneInput.value = userData.phone_number || '';
    if (profileEmailInput) profileEmailInput.value = userData.email || ''; 
}

async function handleUpdateProfileSubmit(event) {
    event.preventDefault(); 
    if (typeof window.clearMessages === 'function') window.clearMessages(); 

    const currentProfileUsernameInput = document.getElementById('profile-username');
    const currentProfilePhoneInput = document.getElementById('profile-phone');

    const username = currentProfileUsernameInput.value;
    const phoneNumber = currentProfilePhoneInput.value;

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
        phoneNumber: phoneNumber.trim() === '' ? null : phoneNumber.trim() 
    };

    if (typeof window.apiCall === 'function') {
        const { ok, data, status } = await window.apiCall('/api/update-profile', 'POST', requestBody);
        if (ok && data.success) {
            if (typeof window.showMessage === 'function') window.showMessage(data.message || '个人信息更新成功！', 'success');
            if (typeof window.checkLoginStatus === 'function') await window.checkLoginStatus(); 
        } else {
            if (typeof window.showMessage === 'function') window.showMessage(data.error || ('更新失败 (' + status + ')'), 'error');
        }
    } else {
        if (typeof window.showMessage === 'function') window.showMessage('发生通讯错误，请重试。', 'error');
    }
}

document.addEventListener('DOMContentLoaded', () => {
    profileUsernameInput = document.getElementById('profile-username');
    profilePhoneInput = document.getElementById('profile-phone');
    profileEmailInput = document.getElementById('profile-email');
    updateProfileForm = document.getElementById('update-profile-form');

    if (updateProfileForm) {
        updateProfileForm.addEventListener('submit', handleUpdateProfileSubmit);
    }

    window.initializePersonalInfoForm = initializePersonalInfoForm;
});
