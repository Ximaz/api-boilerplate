import { Response, Router } from "express";
import authMiddlewareBuilder, { AuthenticatedRequest } from "../../middlewares/auth.middleware.js";
import { SecurityContext } from "../../security.js";
import { JwtPayload } from "jsonwebtoken";

export default function (
    securityContext: SecurityContext
) {
    const router = Router();
    const authMiddleware = authMiddlewareBuilder(securityContext);

    router.get("/", authMiddleware, function (req: AuthenticatedRequest, res: Response) {
        const jwt = req.jwt as JwtPayload;
        console.log(jwt["username"], jwt["id"]);
        return res.json([1, 2, 3]);
    });

    return router;
}
