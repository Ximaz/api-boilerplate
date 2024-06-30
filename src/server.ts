import express from "express";
import dotenv from "dotenv";
import { securityContext } from "./security.js";
import userController from "./router/api/user.controller.js";
import authController from "./router/api/auth.controller.js";

(async function () {
    dotenv.config();

    const server = express();

    /* Server configuration */
    const HOSTADDR = "0.0.0.0";
    const PORT = parseInt(process.env["PORT"] as string);
    if (undefined === PORT || isNaN(PORT))
        throw new Error("Missing or invalid port in environment variables.");

    const [security, securityError] = await securityContext(
        process.env["JWT_SECRET_KEY"] as string,
        process.env["JOSE_PUBLIC_KEY"] as string,
        process.env["JOSE_PRIVATE_KEY"] as string,
        process.env["JWT_ISSUER"] as string
    );
    if (null !== securityError) throw securityError;
    if (null === security) throw new Error("Unreachable");

    server.use("/api/auth", authController(security));
    server.use("/api/users", userController(security));

    server.listen(PORT, HOSTADDR, function () {
        console.log(`REST API Started at http://${HOSTADDR}:${PORT}`);
    });
})().catch(console.error);
