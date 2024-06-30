import { verifyJWE, SecurityContext } from "../security.js";
import { Request, Response, NextFunction } from "express";
import { JwtPayload } from "jsonwebtoken";

export interface AuthenticatedRequest extends Request {
    jwt?: JwtPayload;
}

export type AuthMiddlewareType = (
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction
) => void;

export default function (securityContext: SecurityContext) {
    return async function (req: Request, res: Response, next: NextFunction) {
        const authorization = req.headers["authorization"];
        if (undefined === authorization)
            return res
                .status(401)
                .json({ error: "Missing 'Authorization' HTTP header." });
        const jweMatch = /^Bearer (.*)$/.exec(authorization);
        if (null === jweMatch || 2 !== jweMatch.length)
            return res
                .status(401)
                .json({ error: "Invalid 'Authorization' HTTP header." });
        const jwe = jweMatch[1];
        const [payload, error] = await verifyJWE(
            jwe,
            securityContext.jwtSecretKey,
            securityContext.josePrivateKey,
            {
                issuer: securityContext.issuer,
                checkExpiration: true,
            }
        );
        if (null !== error)
            return res.status(500).json({ error: (error as Error).toString() });
        if (null === payload) throw new Error("Unreachable");
        Object.assign(req, { jwt: payload });
        return next();
    };
}
