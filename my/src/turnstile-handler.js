// Cloudflare Turnstile 验证处理 / Cloudflare Turnstile verification handling

/**
 * 验证 Cloudflare Turnstile 令牌。
 * Verifies a Cloudflare Turnstile token.
 * @param {string} token The Turnstile token from the client.
 * @param {string} secretKey The Turnstile secret key from environment variables.
 * @param {string} [remoteip] The client's IP address (optional).
 * @returns {Promise<{success: boolean, error?: string, 'error-codes'?: string[]}>} Verification result.
 */
export async function verifyTurnstileToken(token, secretKey, remoteip) {
    if (!token) {
        return { success: false, error: '缺少 Turnstile 令牌' }; // Missing Turnstile token
    }
    if (!secretKey) {
        console.error("TURNSTILE_SECRET_KEY is not configured in worker environment.");
        return { success: false, error: 'Turnstile 密钥未配置' }; // Turnstile secret key not configured
    }

    let formData = new FormData();
    formData.append('secret', secretKey);
    formData.append('response', token);
    if (remoteip) { // 可选：传递客户端的 IP 地址 / Optional: pass the client's IP address
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
            console.warn('Turnstile verification failed:', outcome);
            return { success: false, error: 'Turnstile 验证失败', 'error-codes': outcome['error-codes'] || [] }; // Turnstile verification failed
        }
    } catch (error) {
        console.error("[Turnstile Verification] Exception:", error);
        return { success: false, error: 'Turnstile 验证时发生异常' }; // Exception during Turnstile verification
    }
}
