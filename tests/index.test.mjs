// noinspection SpellCheckingInspection

import {describe, it} from "node:test";
import {strictEqual}  from "node:assert";

import {createJwt, getPayloadJwt, isTokenJwt, validateJwt} from "../index.mjs";

describe("jwt", () => {
    describe("createJwt", () => {
        it("create a JWT", async () => {
            const payload  = {
                "sub" : "1234567890",
                "name": "John Doe",
                "iat" : 1516239022,
            };
            const key      = "qwertyuiopasdfghjklzxcvbnm123456";
            const actual   = await createJwt(payload, key);
            const expected = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9." +
                "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ." +
                "qm9F4njElMyEvCFcXqH5MwGowpoDjRt91mIWyOUr-7s";
            strictEqual(actual, expected);
        });
    });

    it("create a JWT 2", async () => {
        const payload  = {
            "iss"      : "Online JWT Builder",
            "iat"      : 1725540872,
            "exp"      : 1757076872,
            "aud"      : "www.example.com",
            "sub"      : "jrocket@example.com",
            "GivenName": "Johnny",
            "Surname"  : "Rocket",
            "Email"    : "jrocket@example.com",
            "Role"     : [
                "Manager",
                "Project Administrator",
            ],
        };
        const key      = "qwertyuiopasdfghjklzxcvbnm123456";
        const actual   = await createJwt(payload, key);
        const expected = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9." +
            "eyJpc3MiOiJPbmxpbmUgSldUIEJ1aWxkZXIiLCJpYXQiOjE3MjU1NDA4NzIsImV4cCI6MTc1NzA3Njg3MiwiYXVkIjoid3d3LmV4YW1wbGUuY29tIiwic3ViIjoianJvY2tldEBleGFtcGxlLmNvbSIsIkdpdmVuTmFtZSI6IkpvaG5ueSIsIlN1cm5hbWUiOiJSb2NrZXQiLCJFbWFpbCI6Impyb2NrZXRAZXhhbXBsZS5jb20iLCJSb2xlIjpbIk1hbmFnZXIiLCJQcm9qZWN0IEFkbWluaXN0cmF0b3IiXX0." +
            "E9fgo0_bRYyz-yb6m5QWTtY81Lt4KcPOZQJlayWWuhE";
        strictEqual(actual, expected);
    });

    describe("isTokenJwt", () => {
        it("recognises a valid token", async () => {
            const payload = {
                "iss": "forexsb.com",
                "iat": 1725540872,
                "exp": 1757076872,
                "aud": "forexsb.com",
                "sub": "jrocket@example.com",
            };
            const key    = "1234";
            const jwt    = await createJwt(payload, key);
            const auth   = `Bearer ${jwt}`;
            const actual = isTokenJwt(auth);
            strictEqual(actual, true);
        });
        it("No Bearer", async () => {
            const payload = {
                "iss": "forexsb.com",
                "iat": 1725540872,
                "exp": 1757076872,
                "aud": "forexsb.com",
                "sub": "jrocket@example.com",
            };
            const key    = "1234";
            const jwt    = await createJwt(payload, key);
            const auth   = `Token ${jwt}`;
            const actual = isTokenJwt(auth);
            strictEqual(actual, false);
        });
        it("No token", async () => {
            const auth   = "Bearer abc.def.123";
            const actual = isTokenJwt(auth);
            strictEqual(actual, false);
        });
    });
    describe("validateJWT", () => {
        it("validate a JWT", async () => {
            const jwt    = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9." +
                "eyJpc3MiOiJmb3JleHNiLmNvbSIsImlhdCI6MTcyNTU0MDg3MiwiZXhwIjoxNzU3MDc2ODcyLCJhdWQiOiJmb3JleHNiLmNvbS9lYS1zdHVkaW8iLCJzdWIiOiJpbmZvQGZvcmV4c2IuY29tIn0." +
                "I0PqXCFyjlrFLgzTg_H2aPEbsOfPGNJJPwnLfG2KCe4";
            const key    = "supersecret";
            const actual = await validateJwt(jwt, key);
            strictEqual(actual, true);
        });
    });

    describe("getPayloadJwt", () => {
        it("get the payload from a JWT", () => {
            const jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9." +
                "eyJpc3MiOiJmb3JleHNiLmNvbSIsImlhdCI6MTcyNTU0MDg3MiwiZXhwIjoxNzU3MDc2ODcyLCJhdWQiOiJmb3JleHNiLmNvbS9lYS1zdHVkaW8iLCJzdWIiOiJpbmZvQGZvcmV4c2IuY29tIn0." +
                "I0PqXCFyjlrFLgzTg_H2aPEbsOfPGNJJPwnLfG2KCe4";
            const actual   = getPayloadJwt(jwt);
            const expected = {
                "iss": "forexsb.com",
                "iat": 1725540872,
                "exp": 1757076872,
                "aud": "forexsb.com/ea-studio",
                "sub": "info@forexsb.com",
            };
            strictEqual(JSON.stringify(actual), JSON.stringify(expected));
        });
    });
});
