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
