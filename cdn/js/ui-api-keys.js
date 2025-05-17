// 前端脚本 - “私信”选项卡相关逻辑
// Frontend Script - "Messaging" Tab Logic

// DOM 元素引用
let newConversationEmailInput, btnStartNewConversation;
let conversationsListUl, messagesAreaDiv, messagesListDiv, messageInputAreaDiv, messageInputTextarea, btnSendMessage;
let unreadMessagesIndicatorSpan;

// 模块级变量，用于跟踪私信状态
let currentActiveConversationId = null;
let currentUserEmail = null;

/**
 * 初始化私信选项卡相关的 DOM 元素和事件监听器。
 */
function initializeMessagingTab() {
    newConversationEmailInput = document.getElementById('new-conversation-email');
    btnStartNewConversation = document.getElementById('btn-start-new-conversation');
    conversationsListUl = document.getElementById('conversations-list');
    messagesAreaDiv = document.getElementById('messages-area');
    messagesListDiv = document.getElementById('messages-list');
    messageInputAreaDiv = document.getElementById('message-input-area');
    messageInputTextarea = document.getElementById('message-input');
    btnSendMessage = document.getElementById('btn-send-message');
    unreadMessagesIndicatorSpan = document.getElementById('unread-messages-indicator');

    if (btnStartNewConversation) {
        btnStartNewConversation.addEventListener('click', handleStartNewConversation);
    }
    if (btnSendMessage) {
        btnSendMessage.addEventListener('click', handleSendMessage);
    }
    if (messageInputTextarea) {
        messageInputTextarea.addEventListener('keypress', function(event) {
            if (event.key === 'Enter' && !event.shiftKey) {
                event.preventDefault();
                handleSendMessage();
            }
        });
        messageInputTextarea.addEventListener('input', function () {
            this.style.height = 'auto'; // 重置高度以允许缩小
            this.style.height = (this.scrollHeight) + 'px'; // 根据内容调整高度
        });
    }
}

/**
 * 当“私信”选项卡被激活时加载数据。
 */
async function loadMessagingTabData() {
    if (typeof window.clearMessages === 'function') window.clearMessages();

    if (typeof window.apiCall === 'function' && !currentUserEmail) {
        const { ok, data } = await window.apiCall('/api/me');
        if (ok && data.email) {
            currentUserEmail = data.email;
        } else {
            console.error("无法获取当前用户信息，私信功能可能受限。");
            if (typeof window.showMessage === 'function') window.showMessage("无法加载您的用户信息，私信功能可能无法正常使用。", "error");
            if (conversationsListUl) conversationsListUl.innerHTML = '<p style="padding:15px; text-align:center; color: var(--danger-color);">无法加载用户信息。</p>';
            return;
        }
    }

    await loadConversations();
    await updateUnreadMessagesIndicator();

    if (messageInputAreaDiv) messageInputAreaDiv.classList.add('hidden');
    if (messagesListDiv) messagesListDiv.innerHTML = '<p style="text-align:center; color: var(--text-color-muted); margin-top:auto; margin-bottom:auto;">请选择一个对话以查看消息。</p>';
    currentActiveConversationId = null;
}

/**
 * 加载并显示用户的对话列表。
 */
async function loadConversations() {
    if (!conversationsListUl || !currentUserEmail) {
        console.warn("loadConversations: conversationsListUl or currentUserEmail is not available.");
        if (conversationsListUl) conversationsListUl.innerHTML = '<p style="padding:15px; text-align:center; color: var(--text-color-muted);">无法加载对话，用户信息不完整。</p>';
        return;
    }
    conversationsListUl.innerHTML = '<p style="padding:15px; text-align:center; color: var(--text-color-muted);">正在加载对话...</p>';

    if (typeof window.apiCall === 'function') {
        const { ok, data, status } = await window.apiCall('/api/conversations');
        if (ok && data.success && Array.isArray(data.conversations)) {
            displayConversations(data.conversations);
        } else {
            console.error("Failed to load conversations:", data);
            conversationsListUl.innerHTML = `<p style="padding:15px; text-align:center; color: var(--danger-color);">加载对话列表失败: ${data.error || '状态码 ' + status}</p>`;
        }
    } else {
        conversationsListUl.innerHTML = `<p style="padding:15px; text-align:center; color: var(--danger-color);">通讯功能不可用。</p>`;
    }
}

/**
 * 渲染对话列表到 UI。
 * @param {Array} conversations 对话对象数组。
 */
function displayConversations(conversations) {
    if (!conversationsListUl || !currentUserEmail) return;
    if (conversations.length === 0) {
        conversationsListUl.innerHTML = '<p style="padding:15px; text-align:center; color: var(--text-color-muted);">没有对话记录。尝试开始一个新的对话吧！</p>';
        return;
    }
    let html = '';
    conversations.forEach(conv => {
        const otherParticipantDisplay = window.escapeHtml(conv.other_participant_username || conv.other_participant_email);
        let lastMessagePreview = conv.last_message_content ? conv.last_message_content : '<i>开始聊天吧！</i>';
        // 对于Markdown内容，预览时应显示纯文本或截断的纯文本
        if (typeof window.marked === 'function' && conv.last_message_content) {
             // 简单地移除Markdown标记来生成预览，或者使用更复杂的纯文本提取
            lastMessagePreview = window.marked.parse(conv.last_message_content, { sanitize: false, breaks: true }).replace(/<[^>]*>?/gm, '');
        }
        lastMessagePreview = window.escapeHtml(lastMessagePreview);
        if (lastMessagePreview.length > 30) lastMessagePreview = lastMessagePreview.substring(0, 27) + "...";

        const lastMessageTime = conv.last_message_at ? new Date(conv.last_message_at * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '';
        const unreadCount = conv.unread_count > 0 ? `<span class="unread-badge">${conv.unread_count}</span>` : '';
        const isActive = conv.conversation_id === currentActiveConversationId ? 'active-conversation' : '';

        html += `
            <li data-conversation-id="${conv.conversation_id}" data-other-participant-email="${window.escapeHtml(conv.other_participant_email)}" class="${isActive}" title="与 ${otherParticipantDisplay} 的对话">
                <span class="conversation-time">${lastMessageTime}</span>
                <div class="conversation-username">${otherParticipantDisplay} ${unreadCount}</div>
                <div class="conversation-last-message">${conv.last_message_sender === currentUserEmail ? '你: ' : ''}${lastMessagePreview}</div>
            </li>
        `;
    });
    conversationsListUl.innerHTML = html;

    conversationsListUl.querySelectorAll('li').forEach(li => {
        li.addEventListener('click', () => {
            const convId = li.dataset.conversationId;
            const otherUserEmail = li.dataset.otherParticipantEmail;
            handleConversationClick(convId, otherUserEmail);
        });
    });
}

/**
 * 处理对话条目的点击事件。
 */
async function handleConversationClick(conversationId, otherParticipantEmail) {
    if (!conversationId || !otherParticipantEmail) {
        console.error("handleConversationClick: Missing conversationId or otherParticipantEmail");
        return;
    }
    currentActiveConversationId = conversationId;
    if(messageInputTextarea) messageInputTextarea.dataset.receiverEmail = otherParticipantEmail;

    if (conversationsListUl) {
        conversationsListUl.querySelectorAll('li').forEach(li => {
            li.classList.toggle('active-conversation', li.dataset.conversationId === conversationId);
            if (li.dataset.conversationId === conversationId) {
                const badge = li.querySelector('.unread-badge');
                if (badge) badge.classList.add('hidden');
            }
        });
    }

    if (messageInputAreaDiv) messageInputAreaDiv.classList.remove('hidden');
    if (messagesListDiv) messagesListDiv.innerHTML = '<p style="text-align:center; color: var(--text-color-muted); margin-top:auto; margin-bottom:auto;">正在加载消息...</p>';

    await loadMessagesForConversation(conversationId);

    if (typeof window.apiCall === 'function') {
        await window.apiCall(`/api/conversations/${conversationId}/read`, 'POST');
        await updateUnreadMessagesIndicator();
    }
}

/**
 * 加载并显示特定对话的消息。
 */
async function loadMessagesForConversation(conversationId) {
    if (!messagesListDiv || !currentUserEmail) return;

    if (typeof window.apiCall === 'function') {
        const { ok, data, status } = await window.apiCall(`/api/conversations/${conversationId}/messages`);
        if (ok && data.success && Array.isArray(data.messages)) {
            displayMessages(data.messages, currentUserEmail);
        } else {
            messagesListDiv.innerHTML = `<p style="text-align:center; color: var(--danger-color); margin-top:auto; margin-bottom:auto;">加载消息失败: ${data.error || '状态码 ' + status}</p>`;
        }
    }
}

/**
 * 渲染消息列表到 UI。
 * @param {Array} messages 消息对象数组。
 * @param {string} currentEmail 当前登录用户的邮箱。
 */
function displayMessages(messages, currentEmail) {
    if (!messagesListDiv) return;
    if (messages.length === 0) {
        messagesListDiv.innerHTML = '<p style="text-align:center; color: var(--text-color-muted); margin-top:auto; margin-bottom:auto;">还没有消息，开始聊天吧！</p>';
        return;
    }
    let html = '';
    messages.forEach(msg => { // 后端返回的是按 sent_at ASC 排序的
        const isSent = msg.sender_email === currentEmail;
        const senderDisplayName = isSent ? '你' : (window.escapeHtml(msg.sender_username || msg.sender_email));
        const messageTime = new Date(msg.sent_at * 1000).toLocaleString([], { year: 'numeric', month: 'numeric', day: 'numeric', hour: '2-digit', minute: '2-digit' });

        // 解析 Markdown 并清理 HTML
        let messageHtmlContent = '';
        if (typeof window.marked === 'function' && typeof DOMPurify === 'object' && DOMPurify.sanitize) {
            // 配置 marked 以支持换行符 <br>
            messageHtmlContent = DOMPurify.sanitize(window.marked.parse(msg.content || '', { breaks: true, gfm: true }));
        } else {
            messageHtmlContent = window.escapeHtml(msg.content || '').replace(/\n/g, '<br>'); // 降级处理
            if (typeof window.marked !== 'function') console.warn("marked.js not loaded.");
            if (typeof DOMPurify !== 'object' || !DOMPurify.sanitize) console.warn("DOMPurify.js not loaded.");
        }

        html += `
            <div class="message-item ${isSent ? 'sent' : 'received'}">
                <span class="message-sender">${senderDisplayName}</span>
                <div class="message-content">${messageHtmlContent}</div>
                <span class="message-time">${messageTime}</span>
            </div>
        `;
    });
    messagesListDiv.innerHTML = html;
    // 确保滚动到底部以显示最新消息
    messagesListDiv.scrollTop = messagesListDiv.scrollHeight;
}

/**
 * 处理发送消息。
 */
async function handleSendMessage() {
    if (!messageInputTextarea || !currentActiveConversationId || !currentUserEmail) {
        if (typeof window.showMessage === 'function') window.showMessage('请先选择一个对话或确保您已登录。', 'warning');
        return;
    }
    const content = messageInputTextarea.value.trim(); // 用户输入的原始 Markdown
    const receiverEmail = messageInputTextarea.dataset.receiverEmail;

    if (!content) {
        if (typeof window.showMessage === 'function') window.showMessage('消息内容不能为空。', 'warning');
        return;
    }
    if (!receiverEmail) {
        if (typeof window.showMessage === 'function') window.showMessage('无法确定消息接收者，请重新选择对话。', 'error');
        return;
    }

    const requestBody = { receiverEmail: receiverEmail, content: content }; // 发送原始 Markdown

    if (typeof window.apiCall === 'function') {
        if(btnSendMessage) btnSendMessage.disabled = true;
        messageInputTextarea.disabled = true;

        const { ok, data, status } = await window.apiCall('/api/messages', 'POST', requestBody);

        if(btnSendMessage) btnSendMessage.disabled = false;
        messageInputTextarea.disabled = false;

        if (ok && data.success) {
            messageInputTextarea.value = '';
            messageInputTextarea.style.height = 'auto';
            messageInputTextarea.focus();
            await loadMessagesForConversation(currentActiveConversationId);
            await loadConversations();
            await updateUnreadMessagesIndicator();
        } else {
            if (typeof window.showMessage === 'function') window.showMessage(data.error || `发送消息失败 (${status})`, 'error');
        }
    }
}

/**
 * 处理开始新的对话。
 */
async function handleStartNewConversation() {
    if (!newConversationEmailInput || !currentUserEmail) return;
    const receiverEmail = newConversationEmailInput.value.trim();

    if (!receiverEmail) {
        if (typeof window.showMessage === 'function') window.showMessage('请输入对方的邮箱地址。', 'warning');
        return;
    }
    if (receiverEmail === currentUserEmail) {
        if (typeof window.showMessage === 'function') window.showMessage('不能与自己开始对话。', 'warning');
        return;
    }
    if (typeof window.isValidEmail !== 'function' || !window.isValidEmail(receiverEmail)) {
        if (typeof window.showMessage === 'function') window.showMessage('请输入有效的邮箱地址。', 'error');
        return;
    }

    if (typeof window.apiCall === 'function') {
        // 发送一条初始消息以创建或获取对话
        const initialMessageContent = `与 ${currentUserEmail} 的对话已开始。`; // 可以是系统消息或空
        const { ok, data } = await window.apiCall('/api/messages', 'POST', {
            receiverEmail: receiverEmail,
            content: initialMessageContent
        });

        if (ok && data.success && data.conversationId) {
            newConversationEmailInput.value = '';
            await loadConversations();

            // 尝试激活新创建的对话
            // 需要确保 loadConversations 完成后 DOM 更新完毕才能查找元素
            // 最好是在 loadConversations 内部处理激活，或者使用回调/Promise
            setTimeout(() => { // 延迟一点以确保 DOM 更新
                const newConvElement = conversationsListUl.querySelector(`li[data-conversation-id="${data.conversationId}"]`);
                if (newConvElement) {
                    handleConversationClick(data.conversationId, receiverEmail);
                } else {
                    // 如果因为排序等原因没立即显示，至少准备好消息区域
                    currentActiveConversationId = data.conversationId;
                    if(messageInputTextarea) messageInputTextarea.dataset.receiverEmail = receiverEmail;
                    if (messageInputAreaDiv) messageInputAreaDiv.classList.remove('hidden');
                    if (messagesListDiv) messagesListDiv.innerHTML = '<p style="text-align:center; color: var(--text-color-muted); margin-top:auto; margin-bottom:auto;">开始聊天吧！</p>';
                }
            }, 100); // 短暂延迟

            if (typeof window.showMessage === 'function') window.showMessage(`与 ${window.escapeHtml(receiverEmail)} 的对话已开始。`, 'success');

        } else if (data.error === '接收者用户不存在') {
             if (typeof window.showMessage === 'function') window.showMessage(`无法开始对话：用户 ${window.escapeHtml(receiverEmail)} 不存在。`, 'error');
        } else {
            if (typeof window.showMessage === 'function') window.showMessage(`无法与 ${window.escapeHtml(receiverEmail)} 开始对话: ${data.error || '未知错误'}`, 'error');
        }
    }
    newConversationEmailInput.value = '';
}

/**
 * 更新顶部导航栏的未读消息指示器。
 */
async function updateUnreadMessagesIndicator() {
    unreadMessagesIndicatorSpan = unreadMessagesIndicatorSpan || document.getElementById('unread-messages-indicator');
    if (!unreadMessagesIndicatorSpan || !currentUserEmail) return;

    if (typeof window.apiCall === 'function') {
        const { ok, data } = await window.apiCall('/api/messages/unread-count');
        if (ok && data.success && typeof data.unread_count === 'number') {
            if (data.unread_count > 0) {
                unreadMessagesIndicatorSpan.textContent = data.unread_count;
                unreadMessagesIndicatorSpan.classList.remove('hidden');
            } else {
                unreadMessagesIndicatorSpan.classList.add('hidden');
            }
        } else {
            console.warn("获取未读消息数失败。");
            unreadMessagesIndicatorSpan.classList.add('hidden');
        }
    }
}


// DOMContentLoaded 后绑定事件
document.addEventListener('DOMContentLoaded', () => {
    initializeMessagingTab();

    window.loadMessagingTabData = loadMessagingTabData;
    window.updateUnreadMessagesIndicator = updateUnreadMessagesIndicator;
});
