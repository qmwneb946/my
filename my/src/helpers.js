// 通用辅助函数 / Common helper functions

/**
 * 生成一个随机的会话 ID。
 * Generates a random session ID.
 * @returns {Promise<string>} A random session ID.
 */
export async function generateSessionId() {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
}

/**
 * 将 Buffer 编码为 Base32 字符串。
 * Encodes a buffer to a Base32 string.
 * @param {ArrayBuffer} buffer The buffer to encode.
 * @returns {string} The Base32 encoded string.
 */
export function base32Encode(buffer) {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let bits = 0;
    let value = 0;
    let output = "";
    const view = new Uint8Array(buffer); // 使用 Uint8Array 视图来访问 ArrayBuffer
    for (let i = 0; i < view.byteLength; i++) {
        value = (value << 8) | view[i];
        bits += 8;
        while (bits >= 5) {
            output += alphabet[(value >>> (bits - 5)) & 31];
            bits -= 5;
        }
    }
    if (bits > 0) {
        output += alphabet[(value << (5 - bits)) & 31];
    }
    return output;
}

/**
 * 将 Base32 字符串解码为 ArrayBuffer。
 * Decodes a Base32 string to an ArrayBuffer.
 * @param {string} base32String The Base32 string to decode.
 * @returns {ArrayBuffer} The decoded ArrayBuffer.
 * @throws {Error} If an invalid Base32 character is found.
 */
export function base32Decode(base32String) {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    const base32Lookup = alphabet.split('').reduce((acc, char, i) => {
        acc[char] = i;
        return acc;
    }, {});

    let bits = 0;
    let value = 0;
    let buffer = [];
    const cleanedString = base32String.toUpperCase().replace(/=+$/, '');

    for (let i = 0; i < cleanedString.length; i++) {
        const charValue = base32Lookup[cleanedString[i]];
        if (charValue === undefined) {
            throw new Error("Invalid Base32 character found in secret: " + cleanedString[i]);
        }
        value = (value << 5) | charValue;
        bits += 5;
        if (bits >= 8) {
            buffer.push((value >>> (bits - 8)) & 0xFF);
            bits -= 8;
        }
    }
    return new Uint8Array(buffer).buffer;
}

/**
 * 生成一个新的 TOTP 密钥 (Base32 编码)。
 * Generates a new TOTP secret (Base32 encoded).
 * @returns {Promise<string>} A new Base32 encoded TOTP secret.
 */
export async function generateTotpSecret() {
    const buffer = new Uint8Array(20); // 160 位是 TOTP 密钥的常见大小
    crypto.getRandomValues(buffer);
    return base32Encode(buffer.buffer); // base32Encode 需要 ArrayBuffer
}

/**
 * 根据 Base32 密钥验证 TOTP 代码。
 * Verifies a TOTP code against a Base32 secret.
 * @param {string} base32Secret The Base32 encoded secret.
 * @param {string} userProvidedCode The 6-digit code provided by the user.
 * @param {number} [timeStep=30] The time step in seconds.
 * @param {number} [window=1] The number of time steps to check before and after the current one.
 * @returns {Promise<boolean>} True if the code is valid, false otherwise.
 */
export async function verifyTotp(base32Secret, userProvidedCode, timeStep = 30, window = 1) {
    if (!base32Secret || !userProvidedCode || userProvidedCode.length !== 6 || !/^\d{6}$/.test(userProvidedCode)) {
        console.warn("[verifyTotp] Invalid input for TOTP verification.");
        return false;
    }
    try {
        const secretBytes = base32Decode(base32Secret); // 返回 ArrayBuffer
        const hmacKey = await crypto.subtle.importKey(
            "raw", secretBytes, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]
        );
        const currentTimeSeconds = Math.floor(Date.now() / 1000);
        for (let i = -window; i <= window; i++) {
            const counterValue = Math.floor(currentTimeSeconds / timeStep) + i;
            const counterBuffer = new ArrayBuffer(8);
            const counterView = new DataView(counterBuffer);
            // TOTP 计数器是大端序的 / TOTP counter is big-endian
            counterView.setBigUint64(0, BigInt(counterValue), false);
            const hmacResult = await crypto.subtle.sign("HMAC", hmacKey, counterBuffer);
            const hmacBytes = new Uint8Array(hmacResult);
            const offset = hmacBytes[hmacBytes.length - 1] & 0x0f;
            const binary =
                ((hmacBytes[offset] & 0x7f) << 24) |
                ((hmacBytes[offset + 1] & 0xff) << 16) |
                ((hmacBytes[offset + 2] & 0xff) << 8) |
                (hmacBytes[offset + 3] & 0xff);
            const otp = (binary % 1000000).toString().padStart(6, '0');
            if (otp === userProvidedCode) return true;
        }
        return false;
    } catch (error) {
        console.error("[verifyTotp] Error during TOTP verification:", error);
        return false;
    }
}

/**
 * 返回 JSON 格式的响应。
 * Returns a JSON response.
 * @param {object|string} data The data to send in the response.
 * @param {number} [status=200] The HTTP status code.
 * @returns {Response} A Response object.
 */
export function jsonResponse(data, status = 200) {
    const responseData = typeof data === 'object' && data !== null ? data : { message: String(data) };
    return new Response(JSON.stringify(responseData), {
        headers: { 'Content-Type': 'application/json;charset=UTF-8' },
        status: status,
    });
}

/**
 * 使用 SHA-256 哈希密码。
 * Hashes a password using SHA-256.
 * @param {string} password The password to hash.
 * @returns {Promise<string>} The hex-encoded hash of the password.
 */
export async function hashPassword(password) {
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * 验证电子邮件地址格式。
 * Validates an email address format.
 * @param {string} email The email address to validate.
 * @returns {boolean} True if the email format is valid, false otherwise.
 */
export function isValidEmail(email) {
    if (typeof email !== 'string') return false;
    // 基本的电子邮件正则表达式 / Basic email regex
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

/**
 * 以抗时序攻击的方式比较两个字符串。
 * Compares two strings in a way that is resistant to timing attacks.
 * @param {string} a The first string.
 * @param {string} b The second string.
 * @returns {Promise<boolean>} True if the strings are equal, false otherwise.
 */
export async function constantTimeCompare(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string') { return false; }
    // 如果长度不同，直接返回 false (对于哈希比较，长度应该总是相同的)
    // If lengths are different, return false directly (for hash comparison, lengths should always be the same)
    if (a.length !== b.length) { return false; }

    const encoder = new TextEncoder();
    const buffA = encoder.encode(a);
    const buffB = encoder.encode(b);

    // 尝试使用 crypto.subtle.timingSafeEqual (更安全)
    // Try to use crypto.subtle.timingSafeEqual (more secure)
    try {
        if (crypto?.subtle?.timingSafeEqual) {
            // 注意：timingSafeEqual 并非在所有 JS 环境中都可用
            // In Cloudflare Workers, it should be available.
            return await crypto.subtle.timingSafeEqual(buffA, buffB);
        }
    } catch (e) { console.warn("crypto.subtle.timingSafeEqual failed (falling back to manual comparison):", e); }

    // 手动回退比较 (不如 timingSafeEqual 理想，但比直接字符串比较好)
    // Fallback manual comparison (less ideal but better than direct string comparison for timing)
    let result = 0;
    for (let i = 0; i < buffA.length; i++) { result |= buffA[i] ^ buffB[i]; }
    return result === 0;
}

/**
 * 动态确定 OAuth Issuer URL。
 * Dynamically determines the OAuth Issuer URL.
 * @param {object} env The environment object.
 * @param {Request} request The incoming request object.
 * @returns {string} The issuer URL.
 */
export const OAUTH_ISSUER_URL = (env, request) => {
    const url = new URL(request.url);
    return `${url.protocol}//${url.hostname}`;
};

// 外部粘贴 API 的基本 URL / Base URL for an external paste API
export const EXTERNAL_PASTE_API_BASE_URL = "https://cloudpaste-backend.qmwneb946.dpdns.org";

/**
 * 生成一个安全的随机字符串，可用作客户端密钥。
 * Generates a secure random string, suitable for a client secret.
 * @param {number} [length=32] The desired length of the string.
 * @returns {string} A random string.
 */
export function generateClientSecret(length = 32) {
    const array = new Uint8Array(length);
    crypto.getRandomValues(array);
    // 使用 Base64URL 编码以避免特殊字符
    // Use Base64URL encoding to avoid special characters
    let str = btoa(String.fromCharCode.apply(null, array));
    str = str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    return str.slice(0, length); // 确保长度准确 / Ensure exact length
}
