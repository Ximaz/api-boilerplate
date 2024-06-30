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
        if (undefined === authorization) return res.status(403).json(null);
        const jweMatch = /^Bearer (.*)$/.exec(authorization);
        if (null === jweMatch || 2 !== jweMatch.length)
            return res.status(403).json(null);
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
        console.log(payload, error);

        if (null !== error) return res.status(500).json(null);
        if (null === payload) return res.status(403).json(null);
        return next();
    };
}
