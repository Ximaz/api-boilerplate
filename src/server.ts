import express from "express";
import dotenv from "dotenv";
/* import { importJoseKeyPair, forgeJWE, verifyJWE } from "./security.js"; */

dotenv.config();

const server = express();
const HOSTADDR = "0.0.0.0";
const PORT = parseInt(process.env["PORT"] as string);
/* const JWT_SECRET_KEY = process.env["JWT_SECRET_KEY"] as string; */
/* const JOSE_PUBLIC_KEY = process.env["JOSE_PUBLIC_KEY"] as string; */
/* const JOSE_PRIVATE_KEY = process.env["JOSE_PRIVATE_KEY"] as string; */

if (undefined === PORT || isNaN(PORT))
    throw new Error("Missing or invalid port in environment variables.");

server.listen(PORT, HOSTADDR, function () {
    console.log(`REST API Started at http://${HOSTADDR}:${PORT}`);
});

/**
(async function () {
    const [[josePublicKey, josePrivateKey], e1] = await importJoseKeyPair(
        JOSE_PUBLIC_KEY,
        JOSE_PRIVATE_KEY
    );

    if (null !== e1) throw e1;
    if (null === josePublicKey || null === josePrivateKey)
        throw new Error("Unreachable");

    const payload = {
        username: "ximaz",
        age: 20,
    };
    const issuer = "Ximaz";
    const [jwe, e2] = await forgeJWE(
        payload,
        JWT_SECRET_KEY,
        josePublicKey,
        {
            issuer,
            audience: "Mighty Audience",
            expiresIn: "4d"
        }
    );
    console.log(jwe);
    if (null === jwe) throw e2;
    const [decodedPayload, e3] = await verifyJWE(
        jwe,
        JWT_SECRET_KEY,
        josePrivateKey,
        {
            issuer,
            checkExpiration: true
        }
    );
    if (null === decodedPayload) throw e3;
    console.log(decodedPayload);
})();
*/
