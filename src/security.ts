import JWT from "jsonwebtoken";
import {
    CompactEncrypt,
    compactDecrypt,
    importJWK,
    generateKeyPair,
    exportJWK,
    KeyLike,
    GenerateKeyPairResult,
    JWK,
} from "jose";
import { RSA_JWK, jwk2pem, pem2jwk } from "pem-jwk";

const JOSE_ALG = "RSA-OAEP";
const JOSE_ENC = "A256GCM";
const JWT_ALGORITHM = "HS512";

/**
 * @brief Exports a public and a private key to respectively encrypt and
 * decrypt JWT. Returns public and private key in an RSA PEM format.
 * @returns [[publicKeyPEM, privateKeyPEM]?, error?]
 */
export async function exportJoseKeyPair(): Promise<
    [[string | null, string | null], null | unknown]
> {
    let keys: GenerateKeyPairResult<KeyLike>;

    try {
        keys = await generateKeyPair(JOSE_ALG, {
            modulusLength: 4096,
        });
    } catch (e) {
        return [[null, null], e];
    }

    let josePublicKey: JWK;
    try {
        josePublicKey = await exportJWK(keys.publicKey);
    } catch (e) {
        return [[null, null], e];
    }

    let josePrivateKey: JWK;
    try {
        josePrivateKey = await exportJWK(keys.privateKey);
    } catch (e) {
        return [[null, null], e];
    }

    let josePublicKeyPEM: string;
    try {
        josePublicKeyPEM = jwk2pem(josePublicKey as RSA_JWK);
    } catch (e) {
        return [[null, null], e];
    }

    let josePrivateKeyPEM: string;
    try {
        josePrivateKeyPEM = jwk2pem(josePrivateKey as RSA_JWK);
    } catch (e) {
        return [[null, null], e];
    }

    return [[josePublicKeyPEM, josePrivateKeyPEM], null];
}

/**
 * @brief Imports a public and a private key to respectively encrypt and
 * decrypt JWT. The format of the public and private key is PEM. The keys MUST
 * BE RSA keys.
 * @param josePublicKeyPEM the RSA public key used to encrypt JWT in PEM format.
 * @param josePrivateKeyPEM the RSA private key used to dencrypt JWT in PEM format.
 * @returns [[publicKey, privateKey]?, error?]
 */
export async function importJoseKeyPair(
    josePublicKeyPEM: string,
    josePrivateKeyPEM: string
): Promise<
    [[KeyLike | Uint8Array | null, KeyLike | Uint8Array | null], null | unknown]
> {
    let josePublicKeyJWK: JWK;
    try {
        josePublicKeyJWK = pem2jwk(josePublicKeyPEM);
    } catch (e) {
        return [[null, null], e];
    }

    let josePrivateKeyJWK: JWK;
    try {
        josePrivateKeyJWK = pem2jwk(josePrivateKeyPEM);
    } catch (e) {
        return [[null, null], e];
    }

    let josePublicKey: KeyLike | Uint8Array;
    try {
        josePublicKey = await importJWK(josePublicKeyJWK, JOSE_ALG);
    } catch (e) {
        return [[null, null], e];
    }

    let josePrivateKey: KeyLike | Uint8Array;
    try {
        josePrivateKey = await importJWK(josePrivateKeyJWK, JOSE_ALG);
    } catch (e) {
        return [[null, null], e];
    }

    return [[josePublicKey, josePrivateKey], null];
}

interface ForgeJWEOptions {
    issuer: string,
    audience?: string,
    expiresIn?: string | number
};

/**
 * @brief Signs and encrypts a JWT into a JWE.
 * @param payload the JSON object to serialize.
 * @param jwtSecretKey the JWT secret key used to sign the JWT.
 * @param josePublicKey the JOSE public key used to encrypt the signed JWT.
 * @param options the JWT issuer, the possible audience, and the expiration timespan.
 */
export async function forgeJWE(
    payload: object,
    jwtSecretKey: string,
    josePublicKey: KeyLike | Uint8Array,
    options: ForgeJWEOptions
): Promise<[null | string, null | unknown]> {
    /* Ensure that the JWT secret key is 32 bytes wide. */
    if (32 !== jwtSecretKey.length)
        return [null, new Error("The JWT secret key must be 32 bytes.")];

    /* Sign the JWT using the secret key. */
    let signedJWT: string;
    try {
        signedJWT = JWT.sign(payload, jwtSecretKey, {
            algorithm: JWT_ALGORITHM,
            allowInsecureKeySizes: false,
            allowInvalidAsymmetricKeyTypes: false,
            encoding: "utf-8",
            ...options
        });
    } catch (e) {
        return [null, e];
    }

    /* Encode the signed JWT. */
    const encoder = new TextEncoder();
    let encrypted: CompactEncrypt;
    try {
        encrypted = new CompactEncrypt(
            encoder.encode(signedJWT)
        ).setProtectedHeader({ alg: JOSE_ALG, enc: JOSE_ENC });
    } catch (e) {
        return [null, e];
    }

    /* Encrypt the encoded signed JWT. */
    try {
        return [await encrypted.encrypt(josePublicKey), null];
    } catch (e) {
        return [null, e];
    }
}

interface verifyJWEOptions {
    issuer: string,
    checkExpiration?: boolean
};

/**
 * @brief Decrypts and verify a JWE.
 * @param jwe the encrypted signed JWT to verify.
 * @param jwtSecretKey the JWT secret key used to sign the JWT.
 * @param josePrivateKey the JOSE private key used to decrypt the signed JWT.
 * @param issuer the issuer of the JWT, most of the time it's the project name.
 * @param checkExpiration whether or not to check for token expiration.
 */
export async function verifyJWE(
    jwe: string,
    jwtSecretKey: string,
    josePrivateKey: KeyLike | Uint8Array,
    options: verifyJWEOptions
): Promise<[null | JWT.Jwt, null | unknown]> {
    /* Decrypt the JWE */
    let encodedSignedJWT: Uint8Array;
    try {
        encodedSignedJWT = (
            await compactDecrypt(jwe, josePrivateKey, {
                keyManagementAlgorithms: [JOSE_ALG],
                contentEncryptionAlgorithms: [JOSE_ENC],
            })
        ).plaintext;
    } catch (e) {
        return [null, e];
    }

    /* Decode the encoded signed JWT */
    const decoder = new TextDecoder();
    let signedJWT: string;
    try {
        signedJWT = decoder.decode(encodedSignedJWT);
    } catch (e) {
        return [null, e];
    }

    /* Match the decoded signed JWT with strict settings. */
    try {
        return [
            JWT.verify(signedJWT, jwtSecretKey, {
                complete: true,
                issuer: options.issuer,
                algorithms: [JWT_ALGORITHM],
                ignoreExpiration: false === options.checkExpiration,
            }),
            null,
        ];
    } catch (e) {
        return [null, e];
    }
}
