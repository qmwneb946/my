export async function verifyTurnstileToken(token, secretKey, remoteip) {
    if (!token) {
        return { success: false, error: '缺少 Turnstile 令牌' }; 
    }
    if (!secretKey) {
        return { success: false, error: 'Turnstile 密钥未配置' }; 
    }

    let formData = new FormData();
    formData.append('secret', secretKey);
    formData.append('response', token);
    if (remoteip) { 
        formData.append('remoteip', remoteip);
    }

    try {
        const response = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
            method: 'POST',
            body: formData,
        });
        const outcome = await response.json();
        if (outcome.success) {
            return { success: true };
        } else {
            return { success: false, error: 'Turnstile 验证失败', 'error-codes': outcome['error-codes'] || [] }; 
        }
    } catch (error) {
        return { success: false, error: 'Turnstile 验证时发生异常' }; 
    }
}
