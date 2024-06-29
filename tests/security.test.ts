import {
    exportJoseKeyPair,
    importJoseKeyPair,
    forgeJWE,
    verifyJWE,
} from "../dist/src/security.js";

const JWT_SECRET_KEY = "2dd084b1270ce3add8c6864022f0ff4d";
const issuer = "ApiBoilerplate";
const audience = "ApiBoilerplateAudience";

test("Exportation and importation of JOSE public and private keys", async function () {
    /* Error handling */
    const [pemKeys, exportJoseKeyPairError] = await exportJoseKeyPair();
    expect(exportJoseKeyPairError).toBeNull();
    expect(pemKeys.length).toBe(2);

    /* Key export verification */
    const [josePublicKeyPEM, josePrivateKeyPEM] = pemKeys;
    if (typeof josePublicKeyPEM !== "string") return expect(0).toBe(1);
    if (typeof josePrivateKeyPEM !== "string") return expect(0).toBe(1);

    /*
     ** To ensure the public key is the first element of the list, and the
     ** private key is the second one, we can compare their length. The public
     ** key length should be less than the private key length.
     */
    expect(josePublicKeyPEM.length).toBeLessThan(josePrivateKeyPEM.length);

    const [keys, importJoseKeyPairError] = await importJoseKeyPair(
        josePublicKeyPEM,
        josePrivateKeyPEM
    );
    expect(importJoseKeyPairError).toBeNull();
    expect(keys.length).toBe(2);
    const [josePublicKey, josePrivateKey] = keys;
    expect(josePublicKey).not.toBeNull();
    expect(josePrivateKey).not.toBeNull();
});

test("Forging and verifying JWE", async function () {
    const [[josePublicKeyPEM, josePrivateKeyPEM]] = await exportJoseKeyPair();
    const [[josePublicKey, josePrivateKey]] = await importJoseKeyPair(
        josePublicKeyPEM,
        josePrivateKeyPEM
    );
    const payload = {
        username: "ximaz",
        age: 20,
    };
    const [jwe, forgeJWEError] = await forgeJWE(
        payload,
        JWT_SECRET_KEY,
        josePublicKey,
        {
            issuer,
            audience,
        }
    );
    expect(forgeJWEError).toBeNull();
    const [decodedPayload, verifyJWEError] = await verifyJWE(
        jwe,
        JWT_SECRET_KEY,
        josePrivateKey,
        {
            issuer,
            checkExpiration: false,
        }
    );
    expect(verifyJWEError).toBeNull();
    expect(payload.username).toBe(decodedPayload.username);
    expect(payload.age).toBe(decodedPayload.age);
});

test("Deal with expired JWE verification", async function () {
    const [[josePublicKeyPEM, josePrivateKeyPEM]] = await exportJoseKeyPair();
    const [[josePublicKey, josePrivateKey]] = await importJoseKeyPair(
        josePublicKeyPEM,
        josePrivateKeyPEM
    );
    const payload = {
        username: "ximaz",
        age: 20,
    };
    const [jwe, forgeJWEError] = await forgeJWE(
        payload,
        JWT_SECRET_KEY,
        josePublicKey,
        {
            issuer,
            audience,
            expiresIn: 0,
        }
    );
    expect(forgeJWEError).toBeNull();
    const [nullPayload, verifyJWEError] = await verifyJWE(
        jwe,
        JWT_SECRET_KEY,
        josePrivateKey,
        {
            issuer,
            checkExpiration: true,
        }
    );
    expect(verifyJWEError.toString()).toBe("TokenExpiredError: jwt expired");
    expect(nullPayload).toBeNull();
});
