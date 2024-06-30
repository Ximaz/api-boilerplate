import { Response, Router } from "express";
import { SecurityContext, forgeJWE } from "../../security.js";

export default function (securityContext: SecurityContext) {
    const router = Router();

    router.get("/", async function (_, res: Response) {
        const [jwe, error] = await forgeJWE(
            { username: "ximaz" },
            securityContext.jwtSecretKey,
            securityContext.josePublicKey,
            { issuer: securityContext.issuer }
        );
        if (null !== error || null === jwe) return res.status(500).json(null);
        return res.json({ jwt: jwe });
    });

    return router;
}
