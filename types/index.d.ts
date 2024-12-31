// types/index.d.ts
// noinspection JSUnusedGlobalSymbols

declare module "@popovmp/jwt" {

    /**
     * Create a JWT
     * @param {Record<string, any>} payload
     * @param {string} key
     * @returns {Promise<string>}
     */
    export async function createJwt(payload: Record<string, any>, key: string): Promise<string>;

    /**
     * Checks if the Authorization header contains a JWT token
     * @param {string|undefined}  authorization - The Authorization header
     * @returns {boolean}
     */
    export function isTokenJwt(authorization: string|undefined): boolean;

    /**
     * Validate JWT signature
     * @param {string} jwt
     * @param {string} key
     * @returns {Promise<boolean>}
     */
    export async function validateJwt(jwt: string, key: string): Promise<boolean>;

    /**
     * Get the payload from a JWT
     * @param {string} jwt
     * @returns {any}
     */
    export function getPayloadJwt(jwt: string): any

    /**
     * Validates a JWT and returns the payload if it is valid.
     * Throws an error with a message "Unauthorized" otherwise.
     * @param {string|undefined }                       authorization - The Authorization header
     * @param {{key: string, iss: string, aud: string}} jwtConfig
     * @returns {Promise<any|undefined>}
     * @throws {Error}
     */
    export async function parseJwtPayload(
        authorization: string | undefined,
        jwtConfig    : { iss: string, aud: string },
    ): Promise<any | undefined>;
}
