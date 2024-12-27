import {base64UrlToString, stringToBase64Url} from "@popovmp/base64";
import {encodeSha256}                         from "@popovmp/sha256";

/**
 * Create a JWT
 * @param {Record<string, any>} payload
 * @param {string} key
 * @returns {Promise<string>}
 */
export async function createJwt(payload, key) {
    const headerBase64Url  = stringToBase64Url(JSON.stringify({typ: "JWT", alg: "HS256"}));
    const payloadBase64Url = stringToBase64Url(JSON.stringify(payload));
    const headerPayload    = `${headerBase64Url}.${payloadBase64Url}`;
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
    if (!authorization.startsWith("Bearer ")) return false;

    /** @type {string} */
    const jwt = authorization.slice(7);

    /** @type {number} */
    const firstDotIndex = jwt.indexOf(".");
    if (firstDotIndex === -1) return false;

    /** @type {number} */
    const lastDotIndex  = jwt.lastIndexOf(".");
    if (lastDotIndex === -1) return false;

    /** @type {string} */
    const headerBase64Url = jwt.slice(0, firstDotIndex);

    /** @type {string} */
    const headerText = base64UrlToString(headerBase64Url);
    if (!headerText.includes("JWT")) return false;

    /** @type {string} */
    const payloadBase64Url = jwt.slice(firstDotIndex + 1, lastDotIndex);

    /** @type {string} */
    const payloadText = base64UrlToString(payloadBase64Url);
    return !!payloadText && payloadText.includes("iss") && payloadText.includes("aud");
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
    const hmac = await encodeSha256(jwt.slice(0, lastDotIndex), key);
    return hmac === jwt.slice(lastDotIndex + 1);
}

/**
 * Get the payload from a JWT
 * @param {string} jwt
 * @returns {any}
 */
export function getPayloadJwt(jwt) {
    const firstDotIndex    = jwt.indexOf(".");
    const lastDotIndex     = jwt.lastIndexOf(".");
    const payloadBase64Url = jwt.slice(firstDotIndex + 1, lastDotIndex);
    const payloadText      = base64UrlToString(payloadBase64Url);
    return JSON.parse(payloadText);
}
