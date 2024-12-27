import {base64UrlToString, stringToBase64Url} from "@popovmp/base64";
import {encodeSha256}                         from "@popovmp/sha256";

/** @type {string} */
const JWT_HEADER = stringToBase64Url(JSON.stringify({typ: "JWT", alg: "HS256"}));

/**
 * Create a JWT
 * @param {Record<string, any>} payload
 * @param {string} key
 * @returns {Promise<string>}
 */
export async function createJwt(payload, key) {
    const payloadBase64Url = stringToBase64Url(JSON.stringify(payload));
    const headerPayload    = `${JWT_HEADER}.${payloadBase64Url}`;
    const encodedSignature = await encodeSha256(headerPayload, key);
    return `${headerPayload}.${encodedSignature}`;
}

/**
 * Checks if the Authorization header contains a JWT token
 * @param {string|undefined}  authorization - The Authorization header
 * @returns {boolean}
 */
export function isTokenJwt(authorization) {
    if (!authorization) return false;

    const bearerJwtHeader = `Bearer ${JWT_HEADER}.`;
    if (!authorization.startsWith(bearerJwtHeader)) return false;

    /** @type {string} */
    const jwtPayloadSignature = authorization.slice(bearerJwtHeader.length);

    /** @type {number} */
    const dotIndex  = jwtPayloadSignature.indexOf(".");
    if (dotIndex === -1) return false;

    /** @type {string} */
    const payloadBase64Url = jwtPayloadSignature.slice(0, dotIndex);

    /** @type {string} */
    const payloadText = base64UrlToString(payloadBase64Url);
    return !!payloadText &&
        payloadText.startsWith("{") &&
        payloadText.includes("iss") &&
        payloadText.includes("aud") &&
        payloadText.includes("exp") &&
        payloadText.includes("sub") &&
        payloadText.endsWith("}");
}

/**
 * Validate JWT signature
 * @param {string} jwt
 * @param {string} key
 * @returns {Promise<boolean>}
 */
export async function validateJwt(jwt, key) {
    const lastDotIndex = jwt.lastIndexOf(".");
    if (lastDotIndex === -1) return false;

    /** @type {string} */
    const hmac = await encodeSha256(jwt.slice(0, lastDotIndex), key);

    return hmac === jwt.slice(lastDotIndex + 1);
}

/**
 * Get the payload from a JWT
 * @param {string} jwt
 * @returns {any}
 */
export function getPayloadJwt(jwt) {
    const lastDotIndex = jwt.lastIndexOf(".");
    if (lastDotIndex === -1) return undefined;

    /** @type {string} */
    const payloadBase64Url = jwt.slice(JWT_HEADER.length + 1, lastDotIndex);

    /** @type {string} */
    const payloadText = base64UrlToString(payloadBase64Url);

    return JSON.parse(payloadText);
}
