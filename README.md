# JWT

A module for working with JWT (JSON Web Tokens) in NodeJS.

```typescript
import {createJwt, getPayloadJwt, validateJwt} from "@popovmp/jwt";

const nowSec = Math.floor(Date.now() / 1000);
const oneHour = 60 * 60;

const payload = {
  "iss": "example.com",
  "iat": nowSec,
  "exp": nowSec + oneHour,
  "aud": "John",
};

// Create JWT with a key
const key = "foobar";
const jwt = await createJwt(payload, key);

// Check is the JWT valid
const isValid = await validateJwt(jwt, key);

// Gets the JWT payload
const payload = getPayloadJwt(jwt);

// Parse Authorization header
const header = "Bearer " + jwt;
const settings = {key: "1234", iss: "example.com", aud: "John"};
const payload = parseJwtPayload(header, settings);
```
