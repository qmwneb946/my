let adminUsersListContainer, adminOauthClientsListContainer;
function formatDateFromTimestamp(timestamp) {
    if (!timestamp) return 'N/A';
    const date = new Date(timestamp * 1000);
    return date.toLocaleString('zh-CN', { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' });
}
async function loadAdminUsersData() {
    adminUsersListContainer = adminUsersListContainer || document.getElementById('admin-users-list-container');
    if (!adminUsersListContainer) return;
    adminUsersListContainer.innerHTML = '<p>正在加载用户列表...</p>';
    const { ok, data, status } = await window.apiCall('/api/admin/users');
    if (ok && data.success && Array.isArray(data.users)) {
        if (data.users.length === 0) {
            adminUsersListContainer.innerHTML = '<p>系统中没有用户。</p>';
            return;
        }
        let tableHtml = `
            <table class="admin-panel-table">
                <thead>
                    <tr>
                        <th>邮箱</th>
                        <th>用户名</th>
                        <th>手机号</th>
                        <th>2FA状态</th>
                        <th>账户状态</th>
                        <th>注册时间</th>
                        <th>操作</th>
                    </tr>
                </thead>
                <tbody>
        `;
        data.users.forEach(user => {
            tableHtml += `
                <tr>
                    <td>${window.escapeHtml(user.email)}</td>
                    <td>${window.escapeHtml(user.username)}</td>
                    <td>${user.phone_number ? window.escapeHtml(user.phone_number) : '未设置'}</td>
                    <td>${user.two_factor_enabled ? '已启用' : '未启用'}</td>
                    <td class="${user.is_active ? 'status-active' : 'status-inactive'}">${user.is_active ? '已激活' : '已禁用'}</td>
                    <td>${formatDateFromTimestamp(user.created_at)}</td>
                    <td class="admin-actions">
                        <button class="button small ${user.is_active ? 'danger' : 'success'}" onclick="toggleUserStatus('${window.escapeHtml(user.email)}', ${!user.is_active})">
                            ${user.is_active ? '禁用' : '激活'}
                        </button>
                    </td>
                </tr>
            `;
        });
        tableHtml += '</tbody></table>';
        adminUsersListContainer.innerHTML = tableHtml;
    } else {
        adminUsersListContainer.innerHTML = `<p style="color: var(--danger-color);">加载用户列表失败: ${data.error || '状态码 ' + status}</p>`;
    }
}
async function toggleUserStatus(userEmail, newStatus) {
    if (typeof window.clearMessages === 'function') window.clearMessages();
    const actionText = newStatus ? '激活' : '禁用';
    if (!confirm(`确定要${actionText}用户 ${userEmail} 吗？`)) return;
    const { ok, data, status } = await window.apiCall(`/api/admin/users/${encodeURIComponent(userEmail)}`, 'PUT', { is_active: newStatus });
    if (ok && data.success) {
        if (typeof window.showMessage === 'function') window.showMessage(data.message || `用户 ${userEmail} 已${actionText}。`, 'success');
        loadAdminUsersData();
    } else {
        if (typeof window.showMessage === 'function') window.showMessage(data.error || `操作失败 (${status})`, 'error');
    }
}
async function loadAdminOauthClientsData() {
    adminOauthClientsListContainer = adminOauthClientsListContainer || document.getElementById('admin-oauth-clients-list-container');
    if (!adminOauthClientsListContainer) return;
    adminOauthClientsListContainer.innerHTML = '<p>正在加载 OAuth 应用列表...</p>';
    const { ok, data, status } = await window.apiCall('/api/admin/oauth/clients');
    if (ok && data.success && Array.isArray(data.clients)) {
        if (data.clients.length === 0) {
            adminOauthClientsListContainer.innerHTML = '<p>系统中没有已注册的 OAuth 应用。</p>';
            return;
        }
        let tableHtml = `
            <table class="admin-panel-table">
                <thead>
                    <tr>
                        <th>应用名称</th>
                        <th>客户端 ID</th>
                        <th>所有者邮箱</th>
                        <th>回调地址</th>
                        <th>状态</th>
                        <th>创建时间</th>
                        <th>操作</th>
                    </tr>
                </thead>
                <tbody>
        `;
        data.clients.forEach(client => {
            let displayRedirectUri = '解析错误';
            try {
                const uris = JSON.parse(client.redirect_uris || '[]');
                displayRedirectUri = uris.length > 0 ? window.escapeHtml(uris[0]) : '未设置';
            } catch(e) {}
            const clientStatus = client.status || 'active';
            tableHtml += `
                <tr>
                    <td>${window.escapeHtml(client.client_name)}</td>
                    <td><code>${window.escapeHtml(client.client_id)}</code></td>
                    <td>${window.escapeHtml(client.owner_email)}</td>
                    <td><code>${displayRedirectUri}</code></td>
                    <td class="${clientStatus === 'active' ? 'status-active' : 'status-suspended'}">${clientStatus === 'active' ? '激活' : '暂停'}</td>
                    <td>${formatDateFromTimestamp(client.created_at)}</td>
                    <td class="admin-actions">
                        <button class="button small ${clientStatus === 'active' ? 'danger' : 'success'}" onclick="toggleOauthClientStatus('${window.escapeHtml(client.client_id)}', '${clientStatus === 'active' ? 'suspended' : 'active'}')">
                            ${clientStatus === 'active' ? '暂停' : '激活'}
                        </button>
                    </td>
                </tr>
            `;
        });
        tableHtml += '</tbody></table>';
        adminOauthClientsListContainer.innerHTML = tableHtml;
    } else {
        adminOauthClientsListContainer.innerHTML = `<p style="color: var(--danger-color);">加载应用列表失败: ${data.error || '状态码 ' + status}</p>`;
    }
}
async function toggleOauthClientStatus(clientId, newStatus) {
    if (typeof window.clearMessages === 'function') window.clearMessages();
    const actionText = newStatus === 'active' ? '激活' : '暂停';
    if (!confirm(`确定要${actionText}应用 ${clientId} 吗？`)) return;
    const { ok, data, status } = await window.apiCall(`/api/admin/oauth/clients/${encodeURIComponent(clientId)}`, 'PUT', { status: newStatus });
    if (ok && data.success) {
        if (typeof window.showMessage === 'function') window.showMessage(data.message || `应用 ${clientId} 已${actionText}。`, 'success');
        loadAdminOauthClientsData();
    } else {
        if (typeof window.showMessage === 'function') window.showMessage(data.error || `操作失败 (${status})`, 'error');
    }
}
window.loadAdminUsersData = loadAdminUsersData;
window.loadAdminOauthClientsData = loadAdminOauthClientsData;
window.toggleUserStatus = toggleUserStatus;
window.toggleOauthClientStatus = toggleOauthClientStatus;
