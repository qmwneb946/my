// 前端脚本 - “API 密钥”选项卡相关逻辑
// Frontend Script - "API Keys" Tab Logic

// DOM 元素引用 (在 DOMContentLoaded 中或首次使用时获取)
let createPasteApiKeyForm, newlyCreatedApiKeyDisplayDiv, newApiKeyInput;
let cloudPcKeyStatusArea, createCloudPcKeyFormContainer, createCloudPcKeyForm, existingCloudPcKeyDisplayDiv;
let cloudPcApiKeyInput, cloudPcUsageCountSpan;

/**
 * 初始化 API 密钥选项卡的数据。
 * 当选项卡被激活时由 main.js 中的 activateTab 调用。
 */
function loadApiKeysTabData() {
    // 加载 Cloud PC 密钥状态
    loadCloudPcKeyStatus();
    // 确保创建云剪贴板密钥的表单中的 Turnstile 被渲染（如果可见）
    const pasteApiKeyTurnstile = document.querySelector('#create-paste-api-key-form .cf-turnstile');
    if (pasteApiKeyTurnstile && pasteApiKeyTurnstile.offsetParent !== null) { // 检查元素是否可见
         if (typeof renderTurnstile === 'function') renderTurnstile(pasteApiKeyTurnstile);
    }
}


/**
 * 处理创建云剪贴板 API 密钥表单提交。
 */
async function handleCreatePasteApiKeySubmit(event) {
    event.preventDefault();
    if (typeof clearMessages === 'function') clearMessages();
    if (newlyCreatedApiKeyDisplayDiv) newlyCreatedApiKeyDisplayDiv.classList.add('hidden');

    const form = event.target;
    const turnstileContainer = form.querySelector('.cf-turnstile');
    const turnstileToken = form.querySelector('[name="cf-turnstile-response"]')?.value;

    if (!turnstileToken && turnstileContainer) {
        if (typeof showMessage === 'function') showMessage('人机验证失败，请重试。', 'error');
        if (typeof resetTurnstileInContainer === 'function') resetTurnstileInContainer(turnstileContainer);
        return;
    }

    const requestBody = { turnstileToken };
    if (typeof apiCall === 'function') {
        const { ok, data, status } = await apiCall('/api/paste-keys', 'POST', requestBody);
        if (turnstileContainer && typeof resetTurnstileInContainer === 'function') resetTurnstileInContainer(turnstileContainer);

        if (ok) {
            if (data.success && data.data && data.data.key) {
                if (newApiKeyInput) newApiKeyInput.value = data.data.key;
                if (newlyCreatedApiKeyDisplayDiv) newlyCreatedApiKeyDisplayDiv.classList.remove('hidden');
                if (typeof showMessage === 'function') showMessage('云剪贴板 API 密钥创建成功！请复制并妥善保管。', 'success');
            } else if (data.success && data.data && data.data.name) {
                 if (typeof showMessage === 'function') showMessage(`API密钥 "${window.escapeHtml(data.data.name)}" 已在外部服务创建成功。但服务未在响应中直接返回密钥值。`, 'info', true);
            } else if (data.message && status >= 200 && status < 300) {
                 if (typeof showMessage === 'function') showMessage(`API密钥创建操作已发送: ${window.escapeHtml(data.message)}`, 'info', true);
            } else {
                 if (typeof showMessage === 'function') showMessage(data.error || data.message || `创建API密钥时外部服务返回了预料之外的响应 (状态: ${status})`, 'warning');
                console.warn("Unexpected response structure from external API for paste key:", data);
            }
        } else {
            if (typeof showMessage === 'function') showMessage(data.error || data.message || `代理创建云剪贴板API密钥时出错 (状态: ${status})`, 'error');
        }
    }
}

/**
 * 加载 Cloud PC 密钥状态。
 */
async function loadCloudPcKeyStatus() {
    cloudPcKeyStatusArea = cloudPcKeyStatusArea || document.getElementById('cloud-pc-key-status-area');
    createCloudPcKeyFormContainer = createCloudPcKeyFormContainer || document.getElementById('create-cloud-pc-key-form-container');
    existingCloudPcKeyDisplayDiv = existingCloudPcKeyDisplayDiv || document.getElementById('existing-cloud-pc-key-display');
    cloudPcApiKeyInput = cloudPcApiKeyInput || document.getElementById('cloud-pc-api-key-value');
    cloudPcUsageCountSpan = cloudPcUsageCountSpan || document.getElementById('cloud-pc-usage-count');


    if (!cloudPcKeyStatusArea) return;
    cloudPcKeyStatusArea.innerHTML = '<p>正在加载 Cloud PC 密钥状态...</p>';
    if (createCloudPcKeyFormContainer) createCloudPcKeyFormContainer.classList.add('hidden');
    if (existingCloudPcKeyDisplayDiv) existingCloudPcKeyDisplayDiv.classList.add('hidden');

    const createFormTurnstile = createCloudPcKeyFormContainer?.querySelector('.cf-turnstile');
    if (createFormTurnstile && typeof removeTurnstile === 'function') removeTurnstile(createFormTurnstile);

    if (typeof apiCall === 'function') {
        const { ok, data, status } = await apiCall('/api/cloudpc-key');
        if (ok) {
            if (data.apiKey) {
                cloudPcKeyStatusArea.innerHTML = ''; // 清空加载状态
                if (cloudPcApiKeyInput) cloudPcApiKeyInput.value = data.apiKey;
                if (cloudPcUsageCountSpan) cloudPcUsageCountSpan.textContent = data.usageCount;
                if (existingCloudPcKeyDisplayDiv) existingCloudPcKeyDisplayDiv.classList.remove('hidden');
                if (createCloudPcKeyFormContainer) createCloudPcKeyFormContainer.classList.add('hidden');
            } else {
                cloudPcKeyStatusArea.innerHTML = '<p>您尚未创建 Cloud PC 密钥。</p>';
                if (createCloudPcKeyFormContainer) {
                    createCloudPcKeyFormContainer.classList.remove('hidden');
                    if (createFormTurnstile && typeof renderTurnstile === 'function') renderTurnstile(createFormTurnstile);
                }
            }
        } else {
            cloudPcKeyStatusArea.innerHTML = `<p style="color: var(--danger-color);">加载 Cloud PC 密钥状态失败: ${data.error || '状态码 ' + status}</p>`;
        }
    }
}

/**
 * 处理创建 Cloud PC 密钥表单提交。
 */
async function handleCreateCloudPcKeySubmit(event) {
    event.preventDefault();
    if (typeof clearMessages === 'function') clearMessages();

    const form = event.target;
    const turnstileContainer = form.querySelector('.cf-turnstile');
    const turnstileToken = form.querySelector('[name="cf-turnstile-response"]')?.value;

    if (!turnstileToken && turnstileContainer) {
        if (typeof showMessage === 'function') showMessage('人机验证失败，请重试。', 'error');
        if (typeof resetTurnstileInContainer === 'function') resetTurnstileInContainer(turnstileContainer);
        return;
    }

    if (typeof apiCall === 'function') {
        const { ok, data, status } = await apiCall('/api/cloudpc-key', 'POST', { turnstileToken });
        if (turnstileContainer && typeof resetTurnstileInContainer === 'function') resetTurnstileInContainer(turnstileContainer);

        if (ok && data.success) {
            if (typeof showMessage === 'function') showMessage(data.message || 'Cloud PC 密钥创建成功！', 'success');
            loadCloudPcKeyStatus(); // 重新加载状态以显示新密钥
        } else {
            if (typeof showMessage === 'function') showMessage(data.error || `创建 Cloud PC 密钥失败 (${status})`);
        }
    }
}


// DOMContentLoaded 后绑定事件
document.addEventListener('DOMContentLoaded', () => {
    // 获取 DOM 元素
    createPasteApiKeyForm = document.getElementById('create-paste-api-key-form');
    newlyCreatedApiKeyDisplayDiv = document.getElementById('newly-created-api-key-display');
    newApiKeyInput = document.getElementById('new-api-key-value');

    cloudPcKeyStatusArea = document.getElementById('cloud-pc-key-status-area');
    createCloudPcKeyFormContainer = document.getElementById('create-cloud-pc-key-form-container');
    createCloudPcKeyForm = document.getElementById('create-cloud-pc-key-form');
    existingCloudPcKeyDisplayDiv = document.getElementById('existing-cloud-pc-key-display');
    cloudPcApiKeyInput = document.getElementById('cloud-pc-api-key-value');
    cloudPcUsageCountSpan = document.getElementById('cloud-pc-usage-count');

    // 绑定事件监听器
    if (createPasteApiKeyForm) {
        createPasteApiKeyForm.addEventListener('submit', handleCreatePasteApiKeySubmit);
    }
    if (createCloudPcKeyForm) {
        createCloudPcKeyForm.addEventListener('submit', handleCreateCloudPcKeySubmit);
    }

    // 将需要在 activateTab 中调用的函数挂载到 window
    // 或者 main.js 可以直接管理这些函数的调用时机 (例如，通过自定义事件)
    window.loadApiKeysTabData = loadApiKeysTabData;
});
