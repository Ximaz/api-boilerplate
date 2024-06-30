import { Request, Response, Router } from "express";
import { SecurityContext, forgeJWE } from "../../security.js";

export default function (securityContext: SecurityContext) {
    const router = Router();

    router.post("/", async function (req: Request, res: Response) {
        const username = req.body.username
            ? (req.body.username as string)?.trim()
            : "";
        const password = (req.body.password as string) || "";

        if (0 === username.length || 0 === password.length)
            return res.status(400).json({ error: "Missing fields." });

        const userId = 1; /* await getUserId(username, password); */
        if (null === userId)
            return res.status(401).json({ error: "Invalid credentials." });

        const [jwe, error] = await forgeJWE(
            { username, id: userId },
            securityContext.jwtSecretKey,
            securityContext.josePublicKey,
            { issuer: securityContext.issuer }
        );
        if (null !== error || null === jwe) return res.status(500).json(null);
        return res.json({ jwt: jwe });
    });

    return router;
}
