export async function generateSessionId() {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
}
export function base32Encode(buffer) {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let bits = 0;
    let value = 0;
    let output = "";
    const view = new Uint8Array(buffer);
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
export async function generateTotpSecret() {
    const buffer = new Uint8Array(20);
    crypto.getRandomValues(buffer);
    return base32Encode(buffer.buffer);
}
export async function verifyTotp(base32Secret, userProvidedCode, timeStep = 30, window = 1) {
    if (!base32Secret || !userProvidedCode || userProvidedCode.length !== 6 || !/^\d{6}$/.test(userProvidedCode)) {
        return false;
    }
    try {
        const secretBytes = base32Decode(base32Secret);
        const hmacKey = await crypto.subtle.importKey(
            "raw", secretBytes, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]
        );
        const currentTimeSeconds = Math.floor(Date.now() / 1000);
        for (let i = -window; i <= window; i++) {
            const counterValue = Math.floor(currentTimeSeconds / timeStep) + i;
            const counterBuffer = new ArrayBuffer(8);
            const counterView = new DataView(counterBuffer);
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
        return false;
    }
}
export function jsonResponse(data, status = 200) {
    const responseData = typeof data === 'object' && data !== null ? data : { message: String(data) };
    return new Response(JSON.stringify(responseData), {
        headers: { 'Content-Type': 'application/json;charset=UTF-8' },
        status: status,
    });
}
export async function hashPassword(password) {
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}
export function isValidEmail(email) {
    if (typeof email !== 'string') return false;
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}
export async function constantTimeCompare(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string') { return false; }
    if (a.length !== b.length) { return false; }
    const encoder = new TextEncoder();
    const buffA = encoder.encode(a);
    const buffB = encoder.encode(b);
    try {
        if (crypto?.subtle?.timingSafeEqual) {
            return await crypto.subtle.timingSafeEqual(buffA, buffB);
        }
    } catch (e) {  }
    let result = 0;
    for (let i = 0; i < buffA.length; i++) { result |= buffA[i] ^ buffB[i]; }
    return result === 0;
}
export const OAUTH_ISSUER_URL = (env, request) => {
    const url = new URL(request.url);
    return `${url.protocol}//${url.hostname}`;
};
export const EXTERNAL_PASTE_API_BASE_URL = "https://cloudpaste-backend.qmwneb946.dpdns.org";
export function generateClientSecret(length = 32) {
    const array = new Uint8Array(length);
    crypto.getRandomValues(array);
    let str = btoa(String.fromCharCode.apply(null, array));
    str = str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    return str.slice(0, length);
}
export function isAdminUser(userEmail, env) {
    if (!userEmail || !env || !env.ADMIN_EMAILS) {
        return false;
    }
    const adminEmails = env.ADMIN_EMAILS.split(',').map(email => email.trim().toLowerCase());
    return adminEmails.includes(userEmail.toLowerCase());
}
