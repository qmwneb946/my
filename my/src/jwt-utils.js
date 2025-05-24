import { OAUTH_ISSUER_URL } from './helpers.js';

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
                name: "RSASSA-PKCS1-v1_5", 
                hash: "SHA-256",
            },
            isPrivateKey ? false : true, 
            keyUsages
        );
    } catch (e) {
        throw new Error(`Failed to import ${isPrivateKey ? 'private' : 'public'} JWK key.`);
    }
}

export async function signJwt(payload, env) {
    if (!env.OAUTH_SIGNING_KEY_PRIVATE) {
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

export async function verifyJwt(token, env) {
    if (!env.OAUTH_SIGNING_KEY_PUBLIC) {
        throw new Error("JWT verification key is not configured.");
    }
    const algorithm = env.OAUTH_SIGNING_ALG || "RS256";
    if (algorithm !== "RS256") {
        throw new Error(`Unsupported JWT verification algorithm: ${algorithm}. Only RS256 is currently supported.`);
    }

    const publicKey = await importJwkKey(env.OAUTH_SIGNING_KEY_PUBLIC, ["verify"], false);

    const parts = token.split('.');
    if (parts.length !== 3) {
        return null;
    }
    const [encodedHeader, encodedPayload, encodedSignature] = parts;
    const dataToVerify = `${encodedHeader}.${encodedPayload}`;

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
            const now = Math.floor(Date.now() / 1000);
            if (payload.exp && payload.exp < now) {
                return null;
            }
            if (payload.nbf && payload.nbf > now) {
                return null;
            }
            return payload;
        } else {
            return null;
        }
    } catch (e) {
        return null;
    }
}

export function generateIdTokenPayload(user, clientId, nonce, scopes, request, env) {
    const now = Math.floor(Date.now() / 1000);
    const issuer = OAUTH_ISSUER_URL(env, request);
    const idTokenLifetime = parseInt(env.ID_TOKEN_LIFETIME_SECONDS || "3600"); 

    const payload = {
        iss: issuer,
        sub: user.email, 
        aud: clientId,
        exp: now + idTokenLifetime,
        iat: now,
        auth_time: now, 
        nonce: nonce,
    };

    if (scopes.includes("email")) {
        payload.email = user.email;
        payload.email_verified = true; 
    }
    if (scopes.includes("profile")) {
        payload.name = user.username; 
        payload.username = user.username; 
    }
    if (user.phone_number && scopes.includes("phone")) { 
        payload.phone_number = user.phone_number;
    }

    return payload;
}

export function generateAccessTokenPayload(userId, clientId, scopes, request, env) {
    const now = Math.floor(Date.now() / 1000);
    const issuer = OAUTH_ISSUER_URL(env, request);
    const accessTokenLifetime = parseInt(env.ACCESS_TOKEN_LIFETIME_SECONDS || "3600"); 

    return {
        iss: issuer,
        sub: userId,
        aud: clientId, 
        exp: now + accessTokenLifetime,
        iat: now,
        client_id: clientId,
        scope: scopes.join(" "), 
    };
}
