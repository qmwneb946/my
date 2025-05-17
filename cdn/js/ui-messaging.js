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
            this.style.height = 'auto';
            this.style.height = (this.scrollHeight) + 'px';
        });
    }
}

/**
 * 当“私信”选项卡被激活时加载数据。
 */
async function loadMessagingTabData() {
    if (typeof window.clearMessages === 'function') window.clearMessages();
    
    // 确保 currentUserEmail 已被设置 (通常在 main.js 的 checkLoginStatus 后或此处获取)
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
    currentActiveConversationId = null; // 重置当前激活的对话ID
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
        let lastMessage = conv.last_message_content ? window.escapeHtml(conv.last_message_content) : '<i>开始聊天吧！</i>';
        if (lastMessage.length > 30) lastMessage = lastMessage.substring(0, 27) + "..."; 
        
        const lastMessageTime = conv.last_message_at ? new Date(conv.last_message_at * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '';
        const unreadCount = conv.unread_count > 0 ? `<span class="unread-badge">${conv.unread_count}</span>` : '';
        const isActive = conv.conversation_id === currentActiveConversationId ? 'active-conversation' : '';

        html += `
            <li data-conversation-id="${conv.conversation_id}" data-other-participant-email="${window.escapeHtml(conv.other_participant_email)}" class="${isActive}" title="与 ${otherParticipantDisplay} 的对话">
                <span class="conversation-time">${lastMessageTime}</span>
                <div class="conversation-username">${otherParticipantDisplay} ${unreadCount}</div>
                <div class="conversation-last-message">${conv.last_message_sender === currentUserEmail ? '你: ' : ''}${lastMessage}</div>
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
 */
function displayMessages(messages, currentEmail) {
    if (!messagesListDiv) return;
    if (messages.length === 0) {
        messagesListDiv.innerHTML = '<p style="text-align:center; color: var(--text-color-muted); margin-top:auto; margin-bottom:auto;">还没有消息，开始聊天吧！</p>';
        return;
    }
    let html = '';
    messages.forEach(msg => {
        const isSent = msg.sender_email === currentEmail;
        const senderDisplayName = isSent ? '你' : (window.escapeHtml(msg.sender_username || msg.sender_email));
        const messageTime = new Date(msg.sent_at * 1000).toLocaleString([], { year: 'numeric', month: 'numeric', day: 'numeric', hour: '2-digit', minute: '2-digit' });

        html += `
            <div class="message-item ${isSent ? 'sent' : 'received'}">
                <span class="message-sender">${senderDisplayName}</span>
                <div class="message-content">${window.escapeHtml(msg.content).replace(/\n/g, '<br>')}</div>
                <span class="message-time">${messageTime}</span>
            </div>
        `;
    });
    messagesListDiv.innerHTML = html;
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
    const content = messageInputTextarea.value.trim();
    const receiverEmail = messageInputTextarea.dataset.receiverEmail;

    if (!content) {
        if (typeof window.showMessage === 'function') window.showMessage('消息内容不能为空。', 'warning');
        return;
    }
    if (!receiverEmail) {
        if (typeof window.showMessage === 'function') window.showMessage('无法确定消息接收者，请重新选择对话。', 'error');
        return;
    }

    const requestBody = { receiverEmail: receiverEmail, content: content };

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
        const { ok, data } = await window.apiCall('/api/messages', 'POST', {
            receiverEmail: receiverEmail,
            content: "(新对话已创建)" // 发送一条初始消息以确保对话创建
        });

        if (ok && data.success && data.conversationId) {
            newConversationEmailInput.value = '';
            await loadConversations(); 
            
            // 尝试激活新创建的对话
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
            if (typeof window.showMessage === 'function') window.showMessage(`与 ${window.escapeHtml(receiverEmail)} 的对话已开始。`, 'success');

        } else if (data.error === '接收者用户不存在') {
             if (typeof window.showMessage === 'function') window.showMessage(`无法开始对话：用户 ${window.escapeHtml(receiverEmail)} 不存在。`, 'error');
        } else {
            if (typeof window.showMessage === 'function') window.showMessage(`无法与 ${window.escapeHtml(receiverEmail)} 开始对话: ${data.error || '未知错误'}`, 'error');
        }
    }
    newConversationEmailInput.value = ''; // 确保清空
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

    // 将需要在 activateTab 中调用的函数挂载到 window
    window.loadMessagingTabData = loadMessagingTabData;
    // 将更新未读消息数的函数也挂载到 window，以便 main.js 在登录后调用
    window.updateUnreadMessagesIndicator = updateUnreadMessagesIndicator;
});
