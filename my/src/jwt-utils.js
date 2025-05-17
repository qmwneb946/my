// JWT (JSON Web Token) 相关的辅助函数
// Functions related to JWT creation, signing, and verification

import { OAUTH_ISSUER_URL } from './helpers.js';

/**
 * 导入 JWK 格式的密钥供 Web Crypto API 使用。
 * @param {string} jwkString JWK 格式的密钥字符串。
 * @param {string[]} keyUsages 密钥用途 (例如 ["sign"] 或 ["verify"])。
 * @param {boolean} isPrivateKey 指示是否为私钥 (影响 extractable 属性)。
 * @returns {Promise<CryptoKey>} 导入的 CryptoKey 对象。
 */
async function importJwkKey(jwkString, keyUsages, isPrivateKey = false) {
    if (!jwkString) {
        throw new Error(`JWK string for ${isPrivateKey ? 'private' : 'public'} key is missing.`);
    }
    try {
        const jwk = JSON.parse(jwkString);
        return await crypto.subtle.importKey(
            "jwk",
            jwk,
            {
                name: "RSASSA-PKCS1-v1_5", // 与 RS256 对应
                hash: "SHA-256",
            },
            isPrivateKey ? false : true, // 私钥通常不可提取，公钥可提取
            keyUsages
        );
    } catch (e) {
        console.error(`Error importing ${isPrivateKey ? 'private' : 'public'} JWK key:`, e, "JWK String:", jwkString);
        throw new Error(`Failed to import ${isPrivateKey ? 'private' : 'public'} JWK key.`);
    }
}

/**
 * 使用 RS256 算法和提供的私钥对 payload 进行签名，生成 JWT。
 * @param {object} payload 要签名的 payload。
 * @param {object} env 环境变量，包含 OAUTH_SIGNING_KEY_PRIVATE 和 OAUTH_SIGNING_ALG。
 * @returns {Promise<string>} 生成的 JWT 字符串。
 */
export async function signJwt(payload, env) {
    if (!env.OAUTH_SIGNING_KEY_PRIVATE) {
        console.error("OAUTH_SIGNING_KEY_PRIVATE is not configured.");
        throw new Error("JWT signing key is not configured.");
    }
    const algorithm = env.OAUTH_SIGNING_ALG || "RS256";
    if (algorithm !== "RS256") {
        throw new Error(`Unsupported JWT signing algorithm: ${algorithm}. Only RS256 is currently supported.`);
    }

    const privateKey = await importJwkKey(env.OAUTH_SIGNING_KEY_PRIVATE, ["sign"], true);

    const header = { alg: algorithm, typ: "JWT" };
    const encodedHeader = btoa(JSON.stringify(header)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
    const encodedPayload = btoa(JSON.stringify(payload)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
    const dataToSign = `${encodedHeader}.${encodedPayload}`;

    const signatureBuffer = await crypto.subtle.sign(
        { name: "RSASSA-PKCS1-v1_5" },
        privateKey,
        new TextEncoder().encode(dataToSign)
    );

    const encodedSignature = btoa(String.fromCharCode(...new Uint8Array(signatureBuffer)))
        .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');

    return `${dataToSign}.${encodedSignature}`;
}

/**
 * 使用 RS256 算法和提供的公钥验证 JWT 签名。
 * @param {string} token JWT 字符串。
 * @param {object} env 环境变量，包含 OAUTH_SIGNING_KEY_PUBLIC 和 OAUTH_SIGNING_ALG。
 * @returns {Promise<object|null>} 如果验证成功，返回解码后的 payload；否则返回 null。
 */
export async function verifyJwt(token, env) {
    if (!env.OAUTH_SIGNING_KEY_PUBLIC) {
        console.error("OAUTH_SIGNING_KEY_PUBLIC is not configured.");
        throw new Error("JWT verification key is not configured.");
    }
    const algorithm = env.OAUTH_SIGNING_ALG || "RS256";
    if (algorithm !== "RS256") {
        throw new Error(`Unsupported JWT verification algorithm: ${algorithm}. Only RS256 is currently supported.`);
    }

    const publicKey = await importJwkKey(env.OAUTH_SIGNING_KEY_PUBLIC, ["verify"], false);

    const parts = token.split('.');
    if (parts.length !== 3) {
        console.warn("Invalid JWT structure (not 3 parts)");
        return null;
    }
    const [encodedHeader, encodedPayload, encodedSignature] = parts;
    const dataToVerify = `${encodedHeader}.${encodedPayload}`;

    // 将 Base64URL 编码的签名转换为 ArrayBuffer
    let signatureString = encodedSignature.replace(/-/g, '+').replace(/_/g, '/');
    while (signatureString.length % 4) {
        signatureString += '=';
    }
    const signatureBytes = Uint8Array.from(atob(signatureString), c => c.charCodeAt(0));

    try {
        const isValid = await crypto.subtle.verify(
            { name: "RSASSA-PKCS1-v1_5" },
            publicKey,
            signatureBytes.buffer,
            new TextEncoder().encode(dataToVerify)
        );

        if (isValid) {
            const payload = JSON.parse(atob(encodedPayload.replace(/-/g, '+').replace(/_/g, '/')));
            // 附加的验证 (例如: 检查 'exp', 'nbf', 'iss', 'aud')
            const now = Math.floor(Date.now() / 1000);
            if (payload.exp && payload.exp < now) {
                console.warn("JWT has expired.");
                return null;
            }
            if (payload.nbf && payload.nbf > now) {
                console.warn("JWT not yet valid (nbf).");
                return null;
            }
            // 可以在这里添加 issuer 和 audience 的验证
            // if (payload.iss !== EXPECTED_ISSUER) return null;
            // if (payload.aud !== EXPECTED_AUDIENCE) return null;
            return payload;
        } else {
            console.warn("JWT signature verification failed.");
            return null;
        }
    } catch (e) {
        console.error("Error during JWT verification:", e);
        return null;
    }
}


/**
 * 为 ID Token 生成标准声明。
 * @param {object} user 用户对象 (例如从数据库获取)。
 * @param {string} clientId OAuth 客户端 ID (audience)。
 * @param {string} nonce OIDC nonce。
 * @param {string[]} scopes 请求的 scopes。
 * @param {object} request 当前请求对象。
 * @param {object} env 环境变量。
 * @returns {object} ID Token 的 payload。
 */
export function generateIdTokenPayload(user, clientId, nonce, scopes, request, env) {
    const now = Math.floor(Date.now() / 1000);
    const issuer = OAUTH_ISSUER_URL(env, request);
    const idTokenLifetime = parseInt(env.ID_TOKEN_LIFETIME_SECONDS || "3600"); // 默认1小时

    const payload = {
        iss: issuer,
        sub: user.email, // 或者用户唯一的 ID
        aud: clientId,
        exp: now + idTokenLifetime,
        iat: now,
        auth_time: now, // 用户认证时间，可以与 iat 相同或更早
        nonce: nonce,
        // 根据 scopes 添加声明
    };

    if (scopes.includes("email")) {
        payload.email = user.email;
        payload.email_verified = true; // 假设已验证，实际应根据用户数据
    }
    if (scopes.includes("profile")) {
        payload.name = user.username; // 或其他名称字段
        payload.username = user.username; // 自定义声明
        // 可以添加其他 profile 相关的声明，如 picture, website, gender, birthdate 等
    }
    if (user.phone_number && scopes.includes("phone")) { // 假设有 'phone' scope
        payload.phone_number = user.phone_number;
        // payload.phone_number_verified = true; // 假设已验证
    }

    return payload;
}

/**
 * 为 Access Token 生成声明 (如果 Access Token 是 JWT)。
 * @param {string} userId 用户 ID 或 subject。
 * @param {string} clientId OAuth 客户端 ID (audience)。
 * @param {string[]} scopes 授予的 scopes。
 * @param {object} request 当前请求对象。
 * @param {object} env 环境变量。
 * @returns {object} Access Token 的 payload。
 */
export function generateAccessTokenPayload(userId, clientId, scopes, request, env) {
    const now = Math.floor(Date.now() / 1000);
    const issuer = OAUTH_ISSUER_URL(env, request);
    const accessTokenLifetime = parseInt(env.ACCESS_TOKEN_LIFETIME_SECONDS || "3600"); // 默认1小时

    return {
        iss: issuer,
        sub: userId,
        aud: clientId, // 或者您的资源服务器的标识符
        exp: now + accessTokenLifetime,
        iat: now,
        client_id: clientId,
        scope: scopes.join(" "), // 空格分隔的 scope 字符串
        // jti: crypto.randomUUID(), // JWT ID，可选
    };
}
