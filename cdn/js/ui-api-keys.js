let apiKeysSettingsList;
let createPasteApiKeyForm, newlyCreatedApiKeyDisplayDiv, newApiKeyInput;
let cloudPcKeyStatusArea, createCloudPcKeyForm, existingCloudPcKeyDisplayDiv;
let cloudPcApiKeyInput, cloudPcUsageCountSpan;
let cloudPcKeyEntryStatusElement;
let btnFetchGreenHubKeys, greenHubCodesDisplayDiv;
function initializeApiKeysTab() {
    apiKeysSettingsList = document.querySelector('#tab-content-api-keys .security-settings-list');
    createPasteApiKeyForm = document.getElementById('create-paste-api-key-form');
    newlyCreatedApiKeyDisplayDiv = document.getElementById('newly-created-api-key-display');
    newApiKeyInput = document.getElementById('new-api-key-value');
    cloudPcKeyStatusArea = document.getElementById('cloud-pc-key-status-area');
    createCloudPcKeyForm = document.getElementById('create-cloud-pc-key-form');
    existingCloudPcKeyDisplayDiv = document.getElementById('existing-cloud-pc-key-display');
    cloudPcApiKeyInput = document.getElementById('cloud-pc-api-key-value');
    cloudPcUsageCountSpan = document.getElementById('cloud-pc-usage-count');
    cloudPcKeyEntryStatusElement = document.getElementById('cloud-pc-key-entry-status');
    btnFetchGreenHubKeys = document.getElementById('btn-fetch-greenhub-keys');
    greenHubCodesDisplayDiv = document.getElementById('greenhub-codes-display');
    if (apiKeysSettingsList) {
        const entries = apiKeysSettingsList.querySelectorAll('.setting-entry');
        entries.forEach(entry => {
            entry.removeEventListener('click', handleApiKeyEntryClick);
            entry.addEventListener('click', handleApiKeyEntryClick);
            const arrow = entry.querySelector('.entry-arrow');
            if (arrow) arrow.textContent = '▶';
            const targetId = entry.dataset.target;
            const targetPanel = document.getElementById(targetId);
            if (targetPanel) {
                targetPanel.classList.add('hidden');
                entry.classList.remove('open');
            }
        });
    }
    if (createPasteApiKeyForm) {
        createPasteApiKeyForm.removeEventListener('submit', handleCreatePasteApiKeySubmit);
        createPasteApiKeyForm.addEventListener('submit', handleCreatePasteApiKeySubmit);
    }
    if (createCloudPcKeyForm) {
        createCloudPcKeyForm.removeEventListener('submit', handleCreateCloudPcKeySubmit);
        createCloudPcKeyForm.addEventListener('submit', handleCreateCloudPcKeySubmit);
    }
    if (btnFetchGreenHubKeys) {
        btnFetchGreenHubKeys.removeEventListener('click', handleFetchGreenHubKeysClick);
        btnFetchGreenHubKeys.addEventListener('click', handleFetchGreenHubKeysClick);
    }
    if (newlyCreatedApiKeyDisplayDiv) newlyCreatedApiKeyDisplayDiv.classList.add('hidden');
    if (greenHubCodesDisplayDiv) greenHubCodesDisplayDiv.innerHTML = '<p class="placeholder-text">点击按钮获取激活码。</p>';
}
function handleApiKeyEntryClick(event) {
    const entry = event.currentTarget;
    const targetId = entry.dataset.target;
    const targetPanel = document.getElementById(targetId);
    const arrow = entry.querySelector('.entry-arrow');
    if (targetPanel) {
        const isOpen = !targetPanel.classList.contains('hidden');
        targetPanel.classList.toggle('hidden');
        entry.classList.toggle('open', !targetPanel.classList.contains('hidden'));
        if (arrow) arrow.textContent = targetPanel.classList.contains('hidden') ? '▶' : '▼';
        if (targetId === 'cloud-pc-key-content-panel' && !targetPanel.classList.contains('hidden') && !targetPanel.dataset.loaded) {
            loadCloudPcKeyStatus();
            targetPanel.dataset.loaded = 'true';
        }
        if (targetId === 'paste-api-key-content-panel' && !targetPanel.classList.contains('hidden')) {
            const turnstile = targetPanel.querySelector('.cf-turnstile');
            if (turnstile && typeof window.renderTurnstile === 'function') {
                window.renderTurnstile(turnstile);
            }
        }
    }
}
function loadApiKeysTabData() {
    initializeApiKeysTab();
}
async function handleCreatePasteApiKeySubmit(event) {
    event.preventDefault();
    if (typeof window.clearMessages === 'function') window.clearMessages();
    if (newlyCreatedApiKeyDisplayDiv) newlyCreatedApiKeyDisplayDiv.classList.add('hidden');
    const form = event.target;
    const turnstileContainer = form.querySelector('.cf-turnstile');
    const turnstileToken = form.querySelector('[name="cf-turnstile-response"]')?.value;
    if (!turnstileToken && turnstileContainer) {
        if (typeof window.showMessage === 'function') window.showMessage('人机验证失败，请重试。', 'error');
        if (typeof window.resetTurnstileInContainer === 'function') window.resetTurnstileInContainer(turnstileContainer);
        return;
    }
    const requestBody = { turnstileToken };
    if (typeof window.apiCall === 'function') {
        const { ok, data, status } = await window.apiCall('/api/paste-keys', 'POST', requestBody);
        if (turnstileContainer && typeof window.resetTurnstileInContainer === 'function') window.resetTurnstileInContainer(turnstileContainer);
        if (ok) {
            if (data.success && data.data && data.data.key) {
                if (newApiKeyInput) newApiKeyInput.value = data.data.key;
                if (newlyCreatedApiKeyDisplayDiv) newlyCreatedApiKeyDisplayDiv.classList.remove('hidden');
                if (typeof window.showMessage === 'function') window.showMessage('云剪贴板 API 密钥创建成功！请复制并妥善保管。', 'success');
            } else if (data.success && data.data && data.data.name) {
                if (typeof window.showMessage === 'function') window.showMessage(`API密钥 "${window.escapeHtml(data.data.name)}" 已在外部服务创建成功。但服务未在响应中直接返回密钥值。`, 'info', true);
            } else if (data.message && status >= 200 && status < 300) {
                if (typeof window.showMessage === 'function') window.showMessage(`API密钥创建操作已发送: ${window.escapeHtml(data.message)}`, 'info', true);
            } else {
                if (typeof window.showMessage === 'function') window.showMessage(data.error || data.message || `创建API密钥时外部服务返回了预料之外的响应 (状态: ${status})`, 'warning');
            }
        } else {
            if (typeof window.showMessage === 'function') window.showMessage(data.error || data.message || `代理创建云剪贴板API密钥时出错 (状态: ${status})`, 'error');
        }
    }
}
async function loadCloudPcKeyStatus() {
    cloudPcKeyStatusArea = cloudPcKeyStatusArea || document.getElementById('cloud-pc-key-status-area');
    createCloudPcKeyForm = createCloudPcKeyForm || document.getElementById('create-cloud-pc-key-form');
    existingCloudPcKeyDisplayDiv = existingCloudPcKeyDisplayDiv || document.getElementById('existing-cloud-pc-key-display');
    cloudPcApiKeyInput = cloudPcApiKeyInput || document.getElementById('cloud-pc-api-key-value');
    cloudPcUsageCountSpan = cloudPcUsageCountSpan || document.getElementById('cloud-pc-usage-count');
    cloudPcKeyEntryStatusElement = cloudPcKeyEntryStatusElement || document.getElementById('cloud-pc-key-entry-status');
    if (!cloudPcKeyStatusArea || !cloudPcKeyEntryStatusElement) {
        return;
    }
    cloudPcKeyStatusArea.innerHTML = '<p>正在加载 Cloud PC 密钥状态...</p>';
    cloudPcKeyEntryStatusElement.textContent = '(正在加载...)';
    cloudPcKeyEntryStatusElement.style.color = 'var(--current-text-muted-color)';
    if (createCloudPcKeyForm) createCloudPcKeyForm.classList.add('hidden');
    if (existingCloudPcKeyDisplayDiv) existingCloudPcKeyDisplayDiv.classList.add('hidden');
    const createFormTurnstile = createCloudPcKeyForm?.querySelector('.cf-turnstile');
    if (createFormTurnstile && typeof window.removeTurnstile === 'function') {
        window.removeTurnstile(createFormTurnstile);
    }
    if (typeof window.apiCall === 'function') {
        try {
            const { ok, data, status } = await window.apiCall('/api/cloudpc-key');
            if (ok) {
                cloudPcKeyStatusArea.innerHTML = '';
                if (data.apiKey) {
                    if (cloudPcApiKeyInput) cloudPcApiKeyInput.value = data.apiKey;
                    if (cloudPcUsageCountSpan) cloudPcUsageCountSpan.textContent = data.usageCount;
                    if (existingCloudPcKeyDisplayDiv) existingCloudPcKeyDisplayDiv.classList.remove('hidden');
                    if (createCloudPcKeyForm) createCloudPcKeyForm.classList.add('hidden');
                    cloudPcKeyEntryStatusElement.textContent = '(已创建)';
                    cloudPcKeyEntryStatusElement.style.color = 'var(--success-color)';
                } else {
                    cloudPcKeyStatusArea.innerHTML = '<p>您尚未创建 Cloud PC 密钥。</p>';
                    if (createCloudPcKeyForm) {
                        createCloudPcKeyForm.classList.remove('hidden');
                        const turnstileInCreateForm = createCloudPcKeyForm.querySelector('.cf-turnstile');
                        if (turnstileInCreateForm && typeof window.renderTurnstile === 'function') {
                            window.renderTurnstile(turnstileInCreateForm);
                        }
                    }
                    cloudPcKeyEntryStatusElement.textContent = '(未创建)';
                    cloudPcKeyEntryStatusElement.style.color = 'var(--current-text-muted-color)';
                }
            } else {
                const errorMessage = data && data.error ? window.escapeHtml(data.error) : `服务器返回状态 ${status}`;
                cloudPcKeyStatusArea.innerHTML = `<p style="color: var(--danger-color);">加载 Cloud PC 密钥状态失败: ${errorMessage}</p>`;
                cloudPcKeyEntryStatusElement.textContent = '(加载失败)';
                cloudPcKeyEntryStatusElement.style.color = 'var(--danger-color)';
            }
        } catch (error) {
            cloudPcKeyStatusArea.innerHTML = `<p style="color: var(--danger-color);">加载密钥时发生意外的前端错误。</p>`;
            cloudPcKeyEntryStatusElement.textContent = '(加载错误)';
            cloudPcKeyEntryStatusElement.style.color = 'var(--danger-color)';
        }
    } else {
        cloudPcKeyStatusArea.innerHTML = `<p style="color: var(--danger-color);">前端 API 调用功能不可用。</p>`;
        cloudPcKeyEntryStatusElement.textContent = '(错误)';
        cloudPcKeyEntryStatusElement.style.color = 'var(--danger-color)';
    }
}
async function handleCreateCloudPcKeySubmit(event) {
    event.preventDefault();
    if (typeof window.clearMessages === 'function') window.clearMessages();
    const form = event.target;
    const turnstileContainer = form.querySelector('.cf-turnstile');
    const turnstileToken = form.querySelector('[name="cf-turnstile-response"]')?.value;
    if (!turnstileToken && turnstileContainer) {
        if (typeof window.showMessage === 'function') window.showMessage('人机验证失败，请重试。', 'error');
        if (typeof window.resetTurnstileInContainer === 'function') window.resetTurnstileInContainer(turnstileContainer);
        return;
    }
    if (typeof window.apiCall === 'function') {
        const { ok, data, status } = await window.apiCall('/api/cloudpc-key', 'POST', { turnstileToken });
        if (turnstileContainer && typeof window.resetTurnstileInContainer === 'function') window.resetTurnstileInContainer(turnstileContainer);
        if (ok && data.success) {
            if (typeof window.showMessage === 'function') window.showMessage(data.message || 'Cloud PC 密钥创建成功！', 'success');
            loadCloudPcKeyStatus();
        } else {
            if (typeof window.showMessage === 'function') window.showMessage(data.error || `创建 Cloud PC 密钥失败 (${status})`, 'error');
        }
    } else {
        if (typeof window.showMessage === 'function') window.showMessage('前端 API 调用功能不可用。', 'error');
    }
}
async function handleFetchGreenHubKeysClick() {
    if (typeof window.clearMessages === 'function') window.clearMessages();
    greenHubCodesDisplayDiv = greenHubCodesDisplayDiv || document.getElementById('greenhub-codes-display');
    if (!greenHubCodesDisplayDiv) {
        if(typeof window.showMessage === 'function') window.showMessage('无法显示激活码，页面元素缺失。', 'error');
        return;
    }
    greenHubCodesDisplayDiv.innerHTML = '<p class="placeholder-text">正在获取激活码...</p>';
    if (typeof window.apiCall === 'function') {
        const { ok, data, status } = await window.apiCall('/api/greenhub-keys', 'GET');
        if (ok && data.success) {
            if (data.license_codes && data.license_codes.length > 0) {
                let listHtml = '<ul class="license-code-list">';
                data.license_codes.forEach(code => {
                    listHtml += `<li>${window.escapeHtml(code)}</li>`;
                });
                listHtml += '</ul>';
                greenHubCodesDisplayDiv.innerHTML = listHtml;
                if(typeof window.showMessage === 'function') window.showMessage('GreenHub 激活码获取成功！', 'success');
            } else {
                greenHubCodesDisplayDiv.innerHTML = `<p class="placeholder-text">${data.message || '未找到激活码。'}</p>`;
                if(typeof window.showMessage === 'function') window.showMessage(data.message || '未找到激活码。', 'info');
            }
        } else {
            const errorMsg = data.error || `获取 GreenHub 激活码失败 (状态: ${status})`;
            greenHubCodesDisplayDiv.innerHTML = `<p class="placeholder-text" style="color: var(--danger-color);">${errorMsg}</p>`;
            if(typeof window.showMessage === 'function') window.showMessage(errorMsg, 'error');
        }
    } else {
        const errorMsg = 'API 调用功能不可用。';
        greenHubCodesDisplayDiv.innerHTML = `<p class="placeholder-text" style="color: var(--danger-color);">${errorMsg}</p>`;
        if(typeof window.showMessage === 'function') window.showMessage(errorMsg, 'error');
    }
}
document.addEventListener('DOMContentLoaded', () => {
    window.initializeApiKeysTab = initializeApiKeysTab;
    window.loadApiKeysTabData = loadApiKeysTabData;
});