let contactSearchInput, btnStartNewConversation;
let conversationsListUl, messagesAreaDiv, messagesListDiv, messageInputAreaDiv, messageInputTextarea, btnSendMessage;
let emptyMessagesPlaceholder;
let newConversationEmailInput;
let currentActiveConversationD1Id = null;
let currentUserEmail = null;
let allConversationsCache = [];
let conversationSocket = null;
let messageIntersectionObserver = null;
let notificationPermissionGranted = false;
let isLoadingMoreMessages = false;
let hasMoreMessagesToLoad = false;
let messagesLoadingIndicatorWrapper, loadMoreMessagesButtonWrapper, loadMoreMessagesButton;
let scrollDebounceTimer = null;

function formatMillisecondsTimestamp(timestamp) {
    const date = new Date(timestamp);
    const year = date.getFullYear();
    const month = (date.getMonth() + 1).toString().padStart(2, '0');
    const day = date.getDate().toString().padStart(2, '0');
    const hours = date.getHours().toString().padStart(2, '0');
    const minutes = date.getMinutes().toString().padStart(2, '0');
    const seconds = date.getSeconds().toString().padStart(2, '0');
    return `${year}/${month}/${day} ${hours}:${minutes}:${seconds}`;
}

async function requestNotificationPermission() {
    if (!('Notification' in window)) {
        return;
    }
    if (Notification.permission === 'granted') {
        notificationPermissionGranted = true;
        return;
    }
    if (Notification.permission !== 'denied') {
        const permission = await Notification.requestPermission();
        if (permission === 'granted') {
            notificationPermissionGranted = true;
        }
    }
}

function showDesktopNotification(title, options, conversationIdToOpen) {
    if (!notificationPermissionGranted || document.hasFocus()) {
        return;
    }
    const notification = new Notification(title, options);
    notification.onclick = () => {
        window.focus();
        if (typeof window.activateTab === 'function' && conversationIdToOpen) {
            window.location.pathname = '/user/messaging';
        }
        notification.close();
    };
}

function initializeMessageObserver() {
    if (messageIntersectionObserver) {
        messageIntersectionObserver.disconnect();
    }
    messageIntersectionObserver = new IntersectionObserver((entries, observer) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                const messageElement = entry.target;
                const messageId = messageElement.dataset.messageId;
                const isUnreadForCurrentUser = messageElement.classList.contains('unread-for-current-user');
                if (messageId && isUnreadForCurrentUser && conversationSocket && conversationSocket.readyState === WebSocket.OPEN) {
                    conversationSocket.send(JSON.stringify({
                        type: "MESSAGE_SEEN",
                        data: { message_id: messageId }
                    }));
                    messageElement.classList.remove('unread-for-current-user');
                    observer.unobserve(messageElement);
                }
            }
        });
    }, { threshold: 0.8 });
}
function observeMessageElement(element) {
    if (messageIntersectionObserver && element) {
        messageIntersectionObserver.observe(element);
    }
}
function initializeMessagingTab() {
    contactSearchInput = document.getElementById('contact-search-input');
    btnStartNewConversation = document.getElementById('btn-start-new-conversation');
    newConversationEmailInput = document.getElementById('new-conversation-email');
    conversationsListUl = document.getElementById('conversations-list');
    messagesAreaDiv = document.getElementById('messages-area');
    messagesListDiv = document.getElementById('messages-list');
    messageInputAreaDiv = document.getElementById('message-input-area');
    messageInputTextarea = document.getElementById('message-input');
    btnSendMessage = document.getElementById('btn-send-message');
    emptyMessagesPlaceholder = messagesListDiv?.querySelector('.empty-messages-placeholder');
    messagesLoadingIndicatorWrapper = document.getElementById('messages-loading-indicator');
    loadMoreMessagesButtonWrapper = document.getElementById('load-more-messages-button-wrapper');
    loadMoreMessagesButton = document.getElementById('load-more-messages-button');


    if (btnStartNewConversation && newConversationEmailInput) {
        btnStartNewConversation.removeEventListener('click', handleNewConversationButtonClick);
        btnStartNewConversation.addEventListener('click', handleNewConversationButtonClick);
        newConversationEmailInput.removeEventListener('keypress', handleNewConversationInputKeypress);
        newConversationEmailInput.addEventListener('keypress', handleNewConversationInputKeypress);
    }
    if(contactSearchInput) {
        contactSearchInput.removeEventListener('input', handleContactSearch);
        contactSearchInput.addEventListener('input', handleContactSearch);
    }
    if (btnSendMessage) {
        btnSendMessage.removeEventListener('click', handleSendMessageClick);
        btnSendMessage.addEventListener('click', handleSendMessageClick);
    }
    if (messageInputTextarea) {
        messageInputTextarea.removeEventListener('keypress', handleMessageInputKeypress);
        messageInputTextarea.addEventListener('keypress', handleMessageInputKeypress);
        messageInputTextarea.removeEventListener('input', handleMessageInputAutosize);
        messageInputTextarea.addEventListener('input', handleMessageInputAutosize);
    }
    if (loadMoreMessagesButton) {
        loadMoreMessagesButton.removeEventListener('click', handleLoadMoreMessagesClick);
        loadMoreMessagesButton.addEventListener('click', handleLoadMoreMessagesClick);
    }
    if (messagesListDiv) {
        messagesListDiv.removeEventListener('scroll', handleMessagesScroll);
        messagesListDiv.addEventListener('scroll', handleMessagesScroll);
    }
    initializeMessageObserver();
    requestNotificationPermission();
}

function handleMessagesScroll() {
    if (scrollDebounceTimer) {
        clearTimeout(scrollDebounceTimer);
    }
    scrollDebounceTimer = setTimeout(() => {
        if (messagesListDiv.scrollTop < 20 && // 接近顶部
            hasMoreMessagesToLoad &&
            !isLoadingMoreMessages &&
            conversationSocket && conversationSocket.readyState === WebSocket.OPEN) {
            handleLoadMoreMessagesClick(true); // true 表示自动加载
        }
    }, 100); // 100ms 防抖
}


function handleNewConversationButtonClick() {
    newConversationEmailInput = newConversationEmailInput || document.getElementById('new-conversation-email');
    if (newConversationEmailInput) {
        const emailValue = newConversationEmailInput.value.trim();
        handleStartNewConversation(emailValue);
    }
}
function handleNewConversationInputKeypress(event) {
    if (event.key === 'Enter') {
        newConversationEmailInput = newConversationEmailInput || document.getElementById('new-conversation-email');
        if (newConversationEmailInput) {
            event.preventDefault();
            const emailValue = newConversationEmailInput.value.trim();
            handleStartNewConversation(emailValue);
        }
    }
}
function handleMessageInputKeypress(event) {
    if (event.key === 'Enter' && !event.shiftKey) {
        event.preventDefault();
        handleSendMessageClick();
    }
}
function handleMessageInputAutosize() {
    this.style.height = 'auto';
    this.style.height = (this.scrollHeight) + 'px';
}
function closeActiveConversationSocket() {
    if (messageIntersectionObserver) {
        messageIntersectionObserver.disconnect();
    }
    if (conversationSocket && (conversationSocket.readyState === WebSocket.OPEN || conversationSocket.readyState === WebSocket.CONNECTING)) {
        conversationSocket.close();
    }
    conversationSocket = null;
    currentActiveConversationD1Id = null;
    hasMoreMessagesToLoad = false;
    isLoadingMoreMessages = false;
    if (loadMoreMessagesButtonWrapper) loadMoreMessagesButtonWrapper.classList.add('hidden');
    if (messagesLoadingIndicatorWrapper) messagesLoadingIndicatorWrapper.classList.add('hidden');
}
window.closeActiveConversationSocket = closeActiveConversationSocket;
async function loadMessagingTabData() {
    initializeMessagingTab();
    if (typeof window.clearMessages === 'function') window.clearMessages();
    conversationsListUl = conversationsListUl || document.getElementById('conversations-list');
    messagesListDiv = messagesListDiv || document.getElementById('messages-list');
    emptyMessagesPlaceholder = emptyMessagesPlaceholder || messagesListDiv?.querySelector('.empty-messages-placeholder');
    messageInputAreaDiv = messageInputAreaDiv || document.getElementById('message-input-area');
    messagesLoadingIndicatorWrapper = messagesLoadingIndicatorWrapper || document.getElementById('messages-loading-indicator');
    loadMoreMessagesButtonWrapper = loadMoreMessagesButtonWrapper || document.getElementById('load-more-messages-button-wrapper');


    if (window.currentUserData && window.currentUserData.email) {
        currentUserEmail = window.currentUserData.email;
    } else {
        const { ok, data } = await window.apiCall('/api/me');
        if (ok && data.email) {
            currentUserEmail = data.email;
            window.currentUserData = data;
        } else {
            if (conversationsListUl) conversationsListUl.innerHTML = '<p class="placeholder-text" style="color: var(--danger-color);">无法加载用户信息，请重新登录。</p>';
            resetActiveConversationUIOnly();
            return;
        }
    }
    if (!currentUserEmail) {
        if (conversationsListUl) conversationsListUl.innerHTML = '<p class="placeholder-text" style="color: var(--danger-color);">用户信息缺失，无法加载对话。</p>';
        resetActiveConversationUIOnly();
        return;
    }
    if (currentActiveConversationD1Id) {
        const activeConv = allConversationsCache.find(c => c.conversation_id === currentActiveConversationD1Id);
        if (activeConv) {
            await handleConversationClick(currentActiveConversationD1Id, activeConv.other_participant_email);
        } else {
             resetActiveConversationUIOnly();
        }
    } else {
        resetActiveConversationUIOnly();
    }
    if (window.userPresenceSocket && window.userPresenceSocket.readyState === WebSocket.OPEN) {
        window.userPresenceSocket.send(JSON.stringify({type: "REQUEST_INITIAL_STATE"}));
    }
}
function displayConversations(conversations) {
    if (typeof window.escapeHtml !== 'function') {
        window.escapeHtml = (unsafe) => {
            if (typeof unsafe !== 'string') return '';
            return unsafe.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
        };
    }
    conversationsListUl = conversationsListUl || document.getElementById('conversations-list');
    if (!conversationsListUl) return;
    if (!currentUserEmail) {
        if (window.currentUserData && window.currentUserData.email) {
            currentUserEmail = window.currentUserData.email;
        } else {
            conversationsListUl.innerHTML = '<p class="placeholder-text" style="color: var(--danger-color);">当前用户信息不可用，无法显示对话列表。</p>';
            return;
        }
    }
    const currentScrollTop = conversationsListUl.scrollTop;
    conversationsListUl.innerHTML = '';
    const sortedConversations = conversations.sort((a,b) => (b.last_message_at || 0) - (a.last_message_at || 0));
    if (sortedConversations.length === 0) {
        let emptyMessage = '<p class="placeholder-text" style="color: var(--text-color-muted);">没有对话记录。尝试发起新对话吧！</p>';
        if (contactSearchInput && contactSearchInput.value.trim() !== '') {
            emptyMessage = '<p class="placeholder-text" style="color: var(--text-color-muted);">未找到相关联系人。</p>';
        }
        conversationsListUl.innerHTML = emptyMessage;
        return;
    }
    let html = '';
    try {
        sortedConversations.forEach(conv => {
            const otherParticipantDisplay = window.escapeHtml(conv.other_participant_username || conv.other_participant_email);
            let lastMessagePreview = conv.last_message_content ? conv.last_message_content : '<i>开始聊天吧！</i>';
            if (typeof window.marked === 'function' && conv.last_message_content) {
                lastMessagePreview = window.marked.parse(conv.last_message_content, { sanitize: true, breaks: true }).replace(/<[^>]*>?/gm, '');
            }
            lastMessagePreview = window.escapeHtml(lastMessagePreview);
            if (lastMessagePreview.length > 25) lastMessagePreview = lastMessagePreview.substring(0, 22) + "...";
            const lastMessageTimeRaw = conv.last_message_at;
            let lastMessageTimeFormatted = '';
            if (lastMessageTimeRaw) {
                try {
                    const date = new Date(lastMessageTimeRaw);
                    const today = new Date();
                    const yesterday = new Date(today);
                    yesterday.setDate(today.getDate() - 1);
                    if (date.toDateString() === today.toDateString()) {
                        lastMessageTimeFormatted = date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
                    } else if (date.toDateString() === yesterday.toDateString()) {
                        lastMessageTimeFormatted = '昨天';
                    } else {
                        lastMessageTimeFormatted = date.toLocaleDateString([], { month: '2-digit', day: '2-digit' });
                    }
                } catch (e) { lastMessageTimeFormatted = ''; }
            }
            const unreadCount = conv.unread_count > 0 ? `<span class="unread-badge">${conv.unread_count}</span>` : '';
            const isActive = conv.conversation_id === currentActiveConversationD1Id ? 'selected' : '';
            const avatarInitial = otherParticipantDisplay.charAt(0).toUpperCase();
            html += `
<li data-conversation-id="${conv.conversation_id}" data-other-participant-email="${window.escapeHtml(conv.other_participant_email)}" class="${isActive}" title="与 ${otherParticipantDisplay} 的对话">
<div class="contact-avatar">${avatarInitial}</div>
<div class="contact-info">
<span class="contact-name">${otherParticipantDisplay}</span>
<span class="contact-last-message">${conv.last_message_sender === currentUserEmail ? '你: ' : ''}${lastMessagePreview}</span>
</div>
<div class="contact-meta">
<span class="contact-time">${lastMessageTimeFormatted}</span>
${unreadCount}
</div>
</li>`;
        });
    } catch (e) {
        conversationsListUl.innerHTML = '<p class="placeholder-text" style="color: var(--danger-color);">渲染对话列表时出错。</p>';
        return;
    }
    conversationsListUl.innerHTML = html;
    conversationsListUl.scrollTop = currentScrollTop;
    conversationsListUl.querySelectorAll('li').forEach(li => {
        li.removeEventListener('click', handleConversationLiClick);
        li.addEventListener('click', handleConversationLiClick);
    });
}
function handleConversationLiClick(event) {
    const li = event.currentTarget;
    const convId = li.dataset.conversationId;
    const otherUserEmail = li.dataset.otherParticipantEmail;
    handleConversationClick(convId, otherUserEmail);
}
function handleContactSearch() {
    contactSearchInput = contactSearchInput || document.getElementById('contact-search-input');
    if (!contactSearchInput) return;
    const searchTerm = contactSearchInput.value.toLowerCase().trim();
    if (!allConversationsCache || !Array.isArray(allConversationsCache)) {
        if(conversationsListUl) conversationsListUl.innerHTML = '<p class="placeholder-text" style="color: var(--text-color-muted);">对话缓存未准备好，无法搜索。</p>';
        return;
    }
    if (!searchTerm) {
        displayConversations(allConversationsCache);
        return;
    }
    const filteredConversations = allConversationsCache.filter(conv => {
        const otherUserUsername = conv.other_participant_username ? String(conv.other_participant_username).toLowerCase() : '';
        const otherUserEmail = conv.other_participant_email ? String(conv.other_participant_email).toLowerCase() : '';
        return otherUserUsername.includes(searchTerm) || otherUserEmail.includes(searchTerm);
    });
    displayConversations(filteredConversations);
}
async function handleConversationClick(conversationD1Id, otherParticipantEmail) {
    if (!conversationD1Id) return;
    if (conversationsListUl) {
        conversationsListUl.querySelectorAll('li').forEach(li => {
            li.classList.toggle('selected', li.dataset.conversationId === conversationD1Id);
        });
    }
    if(messageInputTextarea) messageInputTextarea.dataset.receiverEmail = otherParticipantEmail;
    await connectConversationWebSocket(conversationD1Id);
}
function appendSingleMessageToUI(msg, prepend = false) {
    if (!messagesListDiv || !currentUserEmail) return;
    const isSent = msg.sender_email === currentUserEmail;
    const senderDisplayName = isSent ? '你' : (window.escapeHtml(msg.sender_username || msg.sender_email));
    const messageTime = formatMillisecondsTimestamp(msg.sent_at);
    let messageHtmlContent = '';
    if (typeof window.marked === 'function' && typeof DOMPurify === 'object' && DOMPurify.sanitize) {
        messageHtmlContent = DOMPurify.sanitize(window.marked.parse(msg.content || '', { breaks: true, gfm: true }));
    } else {
        messageHtmlContent = window.escapeHtml(msg.content || '').replace(/\n/g, '<br>');
    }
    const messageItemDiv = document.createElement('div');
    messageItemDiv.className = `message-item ${isSent ? 'sent' : 'received'}`;
    messageItemDiv.dataset.messageId = msg.message_id;
    if (msg.sender_email !== currentUserEmail && msg.is_read === 0) {
        messageItemDiv.classList.add('unread-for-current-user');
    }
    messageItemDiv.innerHTML = `
<span class="message-sender">${senderDisplayName}</span>
<div class="message-content">${messageHtmlContent}</div>
<span class="message-time">${messageTime}</span>`;

    const isNearBottom = messagesListDiv.scrollHeight - messagesListDiv.scrollTop - messagesListDiv.clientHeight < 50;
    const oldScrollHeight = messagesListDiv.scrollHeight;

    if (prepend) {
        messagesListDiv.insertBefore(messageItemDiv, messagesListDiv.firstChild.nextSibling.nextSibling); // Insert after load more button and indicator
    } else {
        messagesListDiv.appendChild(messageItemDiv);
    }

    if (msg.sender_email !== currentUserEmail && msg.is_read === 0) {
        observeMessageElement(messageItemDiv);
    }

    if (prepend) {
        messagesListDiv.scrollTop += (messagesListDiv.scrollHeight - oldScrollHeight);
    } else if (isNearBottom) {
        messagesListDiv.scrollTop = messagesListDiv.scrollHeight;
    }
}
function connectConversationWebSocket(conversationD1Id) {
    return new Promise((resolve, reject) => {
        if (conversationSocket && (conversationSocket.readyState === WebSocket.OPEN || conversationSocket.readyState === WebSocket.CONNECTING)) {
            if (currentActiveConversationD1Id === conversationD1Id) {
                resolve();
                return;
            }
            closeActiveConversationSocket();
        }
        initializeMessageObserver();
        if (!currentUserData || !currentUserData.email) {
            reject(new Error("User not authenticated for conversation WebSocket."));
            return;
        }
        currentActiveConversationD1Id = conversationD1Id;
        if (messagesLoadingIndicatorWrapper) messagesLoadingIndicatorWrapper.classList.remove('hidden');
        if (loadMoreMessagesButtonWrapper) loadMoreMessagesButtonWrapper.classList.add('hidden');

        // Clear previous messages, but keep the load more button and indicator
        if (messagesListDiv) {
            const childrenToKeep = [messagesLoadingIndicatorWrapper, loadMoreMessagesButtonWrapper, emptyMessagesPlaceholder];
            Array.from(messagesListDiv.children).forEach(child => {
                if (!childrenToKeep.includes(child)) {
                    messagesListDiv.removeChild(child);
                }
            });
        }
        if (emptyMessagesPlaceholder) emptyMessagesPlaceholder.classList.add('hidden');


        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsConvUrl = `${protocol}//${window.location.host}/api/ws/conversation/${conversationD1Id}`;
        conversationSocket = new WebSocket(wsConvUrl);
        conversationSocket.onopen = () => {
            if (messageInputAreaDiv) messageInputAreaDiv.classList.remove('hidden');
            hasMoreMessagesToLoad = false;
            resolve();
        };
        conversationSocket.onmessage = (event) => {
            try {
                const message = JSON.parse(event.data);
                if (messagesLoadingIndicatorWrapper) messagesLoadingIndicatorWrapper.classList.add('hidden');
                if (loadMoreMessagesButtonWrapper && loadMoreMessagesButton) {
                     loadMoreMessagesButtonWrapper.classList.toggle('hidden', !hasMoreMessagesToLoad || isLoadingMoreMessages);
                }


                if (message.type === "HISTORICAL_MESSAGE") {
                    appendSingleMessageToUI(message.data, message.prepended);
                    if (!message.prepended) {
                        messagesListDiv.scrollTop = messagesListDiv.scrollHeight;
                    }
                } else if (message.type === "NEW_MESSAGE") {
                    appendSingleMessageToUI(message.data);
                    if (message.data.sender_email !== currentUserEmail && window.userPresenceSocket && window.userPresenceSocket.readyState === WebSocket.OPEN) {
                         window.userPresenceSocket.send(JSON.stringify({type: "REQUEST_CONVERSATIONS_LIST"}));
                    }
                } else if (message.type === "CONNECTION_ESTABLISHED"){
                } else if (message.type === "MESSAGES_READ"){
                } else if (message.type === "MORE_MESSAGES_AVAILABLE") {
                    hasMoreMessagesToLoad = true;
                    if (loadMoreMessagesButtonWrapper) loadMoreMessagesButtonWrapper.classList.remove('hidden');
                } else if (message.type === "NO_MORE_MESSAGES") {
                    hasMoreMessagesToLoad = false;
                    if (loadMoreMessagesButtonWrapper) loadMoreMessagesButtonWrapper.classList.add('hidden');
                } else if (message.type === "ERROR") {
                    if (typeof window.showMessage === 'function') window.showMessage(`对话错误: ${message.data}`, 'error');
                }
            } catch (e) {
                if (messagesLoadingIndicatorWrapper) messagesLoadingIndicatorWrapper.classList.add('hidden');
            } finally {
                isLoadingMoreMessages = false;
                if (loadMoreMessagesButton && loadMoreMessagesButtonWrapper) {
                    loadMoreMessagesButton.disabled = false;
                    loadMoreMessagesButton.textContent = '加载更多...';
                    loadMoreMessagesButtonWrapper.classList.toggle('hidden', !hasMoreMessagesToLoad);
                }
            }
        };
        conversationSocket.onclose = (event) => {
            if (currentActiveConversationD1Id === conversationD1Id) {
                conversationSocket = null;
                currentActiveConversationD1Id = null;
                resetActiveConversationUIOnly();
            }
            if (messagesLoadingIndicatorWrapper) messagesLoadingIndicatorWrapper.classList.add('hidden');
            if (loadMoreMessagesButtonWrapper) loadMoreMessagesButtonWrapper.classList.add('hidden');
        };
        conversationSocket.onerror = (error) => {
            if (currentActiveConversationD1Id === conversationD1Id) {
                 resetActiveConversationUIOnly();
            }
            if (messagesLoadingIndicatorWrapper) messagesLoadingIndicatorWrapper.classList.add('hidden');
            if (loadMoreMessagesButtonWrapper) loadMoreMessagesButtonWrapper.classList.add('hidden');
            reject(error);
        };
    });
}
function handleLoadMoreMessagesClick(isAutoLoad = false) {
    if (!conversationSocket || conversationSocket.readyState !== WebSocket.OPEN || isLoadingMoreMessages || !hasMoreMessagesToLoad) {
        return;
    }
    isLoadingMoreMessages = true;
    if (loadMoreMessagesButtonWrapper && loadMoreMessagesButton) {
        if (!isAutoLoad) { // 如果是手动点击，则显示加载中
            loadMoreMessagesButton.disabled = true;
            loadMoreMessagesButton.textContent = '正在加载...';
        } else { // 如果是自动加载，可以先隐藏按钮，显示 spinner
            loadMoreMessagesButtonWrapper.classList.add('hidden');
            if (messagesLoadingIndicatorWrapper) messagesLoadingIndicatorWrapper.classList.remove('hidden');
        }
    }
    conversationSocket.send(JSON.stringify({ type: "REQUEST_MORE_MESSAGES" }));
}
function resetActiveConversationUIOnly() {
    closeActiveConversationSocket();
    if (messageInputTextarea) {
        messageInputTextarea.value = '';
        messageInputTextarea.removeAttribute('data-receiver-email');
    }
    if (messageInputAreaDiv) messageInputAreaDiv.classList.add('hidden');

    if (messagesListDiv) {
        const childrenToKeep = [messagesLoadingIndicatorWrapper, loadMoreMessagesButtonWrapper, emptyMessagesPlaceholder];
        Array.from(messagesListDiv.children).forEach(child => {
            if (!childrenToKeep.includes(child)) {
                messagesListDiv.removeChild(child);
            }
        });
    }

    if (emptyMessagesPlaceholder && messagesListDiv) {
        emptyMessagesPlaceholder.querySelector('p').textContent = '选择一个联系人开始聊天';
        emptyMessagesPlaceholder.querySelector('span').textContent = '或通过上方输入框发起新的对话。';
        emptyMessagesPlaceholder.classList.remove('hidden');
         if (messagesListDiv.firstChild !== messagesLoadingIndicatorWrapper && messagesLoadingIndicatorWrapper) {
            messagesListDiv.insertBefore(messagesLoadingIndicatorWrapper, messagesListDiv.firstChild);
        }
        if (messagesListDiv.children[1] !== loadMoreMessagesButtonWrapper && loadMoreMessagesButtonWrapper) {
             messagesListDiv.insertBefore(loadMoreMessagesButtonWrapper, messagesListDiv.children[1] || null);
        }
        if (messagesListDiv.lastChild !== emptyMessagesPlaceholder) {
             messagesListDiv.appendChild(emptyMessagesPlaceholder);
        }
    }


    if (conversationsListUl) {
        conversationsListUl.querySelectorAll('li.selected').forEach(li => li.classList.remove('selected'));
    }
    if (messagesLoadingIndicatorWrapper) messagesLoadingIndicatorWrapper.classList.add('hidden');
    if (loadMoreMessagesButtonWrapper) loadMoreMessagesButtonWrapper.classList.add('hidden');
}
function handleSendMessageClick() {
    if (!conversationSocket || conversationSocket.readyState !== WebSocket.OPEN) {
        if(typeof window.showMessage === 'function') window.showMessage('对话连接未建立。', 'error');
        return;
    }
    const content = messageInputTextarea.value.trim();
    if (!content) {
        if(typeof window.showMessage === 'function') window.showMessage('消息内容不能为空。', 'warning');
        return;
    }
    conversationSocket.send(JSON.stringify({
        type: "NEW_MESSAGE",
        data: { content: content }
    }));
    messageInputTextarea.value = '';
    messageInputTextarea.style.height = 'auto';
    messageInputTextarea.focus();
}
async function handleStartNewConversation(receiverEmailFromInput) {
    const localReceiverEmail = receiverEmailFromInput.trim();
    if (!localReceiverEmail) {
        if (typeof window.showMessage === 'function') window.showMessage('请输入对方的邮箱地址。', 'warning');
        return;
    }
    if (!currentUserEmail) {
        if (typeof window.showMessage === 'function') window.showMessage('当前用户信息获取失败。', 'error');
        return;
    }
    if (localReceiverEmail === currentUserEmail) {
        if (typeof window.showMessage === 'function') window.showMessage('不能与自己开始对话。', 'warning');
        return;
    }
    if (typeof window.isValidEmail === 'function' && !window.isValidEmail(localReceiverEmail)) {
        if (typeof window.showMessage === 'function') window.showMessage('请输入有效的邮箱地址。', 'error');
        return;
    }
    const existingConv = allConversationsCache.find(c => c.other_participant_email === localReceiverEmail);
    if (existingConv && existingConv.conversation_id) {
        await handleConversationClick(existingConv.conversation_id, localReceiverEmail);
        if (newConversationEmailInput) newConversationEmailInput.value = '';
        if (typeof window.showMessage === 'function') window.showMessage(`已切换到与 ${window.escapeHtml(localReceiverEmail)} 的对话。`, 'info');
        return;
    }
    if (typeof window.apiCall === 'function') {
        const { ok, data, status } = await window.apiCall('/api/messages', 'POST', {
            receiverEmail: localReceiverEmail,
            content: `与 ${currentUserEmail.split('@')[0]} 的对话已开始。`
        });
        if (ok && data.success && data.conversationId) {
            if (newConversationEmailInput) newConversationEmailInput.value = '';
            if (contactSearchInput) contactSearchInput.value = '';
            if (window.userPresenceSocket && window.userPresenceSocket.readyState === WebSocket.OPEN) {
                 window.userPresenceSocket.send(JSON.stringify({type: "REQUEST_CONVERSATIONS_LIST"}));
            }
            setTimeout(async () => {
                const newlyCreatedConv = allConversationsCache.find(c => c.other_participant_email === localReceiverEmail && c.conversation_id === data.conversationId);
                if (newlyCreatedConv) {
                    await handleConversationClick(data.conversationId, localReceiverEmail);
                } else {
                    await handleConversationClick(data.conversationId, localReceiverEmail);
                }
            }, 500);
            if (typeof window.showMessage === 'function') window.showMessage(`与 ${window.escapeHtml(localReceiverEmail)} 的对话已开始。`, 'success');
        } else if (data.error === '接收者用户不存在' || status === 404) {
            if (typeof window.showMessage === 'function') window.showMessage(`无法开始对话：用户 ${window.escapeHtml(localReceiverEmail)} 不存在。`, 'error');
        } else {
            if (typeof window.showMessage === 'function') window.showMessage(`无法与 ${window.escapeHtml(localReceiverEmail)} 开始对话: ${ (data && (data.error || data.message)) ? window.escapeHtml(data.error || data.message) : '未知错误, 状态: ' + status}`, 'error');
        }
    }
}
window.handleConversationsListUpdate = function(conversationsData) {
    if (!currentUserEmail && window.currentUserData && window.currentUserData.email) {
        currentUserEmail = window.currentUserData.email;
    }
    const oldConversationsSummary = { ...allConversationsCache.reduce((acc, conv) => { acc[conv.conversation_id] = conv; return acc; }, {}) };
    allConversationsCache = conversationsData.map(conv => ({
        conversation_id: conv.conversation_id,
        other_participant_username: conv.other_participant_username,
        other_participant_email: conv.other_participant_email,
        last_message_content: conv.last_message_content,
        last_message_sender: conv.last_message_sender,
        last_message_at: conv.last_message_at,
        unread_count: conv.unread_count,
    }));
    displayConversations(allConversationsCache);
    allConversationsCache.forEach(newConv => {
        const oldConv = oldConversationsSummary[newConv.conversation_id];
        if (newConv.last_message_sender && newConv.last_message_sender !== currentUserEmail && newConv.unread_count > 0) {
            if (!oldConv || newConv.last_message_at > (oldConv.last_message_at || 0)) {
                 const mainContentContainerEl = document.getElementById('main-content')?.querySelector('.container');
                 const isMessagingTabActive = mainContentContainerEl?.classList.contains('messaging-active');
                 const isCurrentConversationActive = newConv.conversation_id === currentActiveConversationD1Id;
                if (!document.hasFocus() || !isMessagingTabActive || !isCurrentConversationActive) {
                    showDesktopNotification(
                        `来自 ${window.escapeHtml(newConv.other_participant_username || newConv.other_participant_email)} 的新消息`,
                        {
                            body: window.escapeHtml(newConv.last_message_content.substring(0, 50) + (newConv.last_message_content.length > 50 ? "..." : "")),
                            icon: '/favicon.ico',
                            tag: `conversation-${newConv.conversation_id}`
                        },
                        newConv.conversation_id
                    );
                }
            }
        }
    });
    if (currentActiveConversationD1Id) {
        const activeConvStillExists = allConversationsCache.some(c => c.conversation_id === currentActiveConversationD1Id);
        if (!activeConvStillExists) {
            resetActiveConversationUIOnly();
        } else {
            const selectedLi = conversationsListUl?.querySelector(`li[data-conversation-id="${currentActiveConversationD1Id}"]`);
            if (selectedLi) selectedLi.classList.add('selected');
        }
    }
};
window.handleSingleConversationUpdate = function(updatedConvData) {
    if (!currentUserEmail && window.currentUserData && window.currentUserData.email) {
        currentUserEmail = window.currentUserData.email;
    }
    const index = allConversationsCache.findIndex(c => c.conversation_id === updatedConvData.conversation_id);
    const oldConvData = index > -1 ? { ...allConversationsCache[index] } : null;
    const mappedData = {
        conversation_id: updatedConvData.conversation_id,
        other_participant_username: updatedConvData.other_participant_username,
        other_participant_email: updatedConvData.other_participant_email,
        last_message_content: updatedConvData.last_message_content,
        last_message_sender: updatedConvData.last_message_sender,
        last_message_at: updatedConvData.last_message_at,
        unread_count: updatedConvData.unread_count,
    };
    if (index > -1) {
        allConversationsCache[index] = { ...allConversationsCache[index], ...mappedData };
    } else {
        allConversationsCache.unshift(mappedData);
    }
    displayConversations(allConversationsCache);
    if (mappedData.last_message_sender && mappedData.last_message_sender !== currentUserEmail && mappedData.unread_count > 0) {
        if (!oldConvData || mappedData.last_message_at > (oldConvData.last_message_at || 0)) {
            const mainContentContainerEl = document.getElementById('main-content')?.querySelector('.container');
            const isMessagingTabActive = mainContentContainerEl?.classList.contains('messaging-active');
            const isCurrentConversationActive = mappedData.conversation_id === currentActiveConversationD1Id;
             if (!document.hasFocus() || !isMessagingTabActive || !isCurrentConversationActive) {
                showDesktopNotification(
                    `来自 ${window.escapeHtml(mappedData.other_participant_username || mappedData.other_participant_email)} 的新消息`,
                    {
                        body: window.escapeHtml(mappedData.last_message_content.substring(0, 50) + (mappedData.last_message_content.length > 50 ? "..." : "")),
                        icon: '/favicon.ico',
                        tag: `conversation-${mappedData.conversation_id}`
                    },
                    mappedData.conversation_id
                );
            }
        }
    }
    if (currentActiveConversationD1Id === updatedConvData.conversation_id) {
        const selectedLi = conversationsListUl?.querySelector(`li[data-conversation-id="${currentActiveConversationD1Id}"]`);
        if (selectedLi) selectedLi.classList.add('selected');
    }
};
window.initializeMessagingTab = initializeMessagingTab;
window.loadMessagingTabData = loadMessagingTabData;
