import type { Request, Response, NextFunction } from "express";
import { validateJWT, type AuthInfo } from "./jwt-validator.js";
import { config } from "../config.js";
import { timingSafeEqual } from "crypto";

declare global {
  namespace Express {
    interface Request {
      auth?: AuthInfo;
    }
  }
}

export async function authMiddleware(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    res.status(401);
    res.setHeader(
      "WWW-Authenticate",
      `Bearer realm="mcp", resource_metadata="${config.mcpServerUrl}/.well-known/oauth-protected-resource"`
    );
    res.json({ error: "Authorization required" });
    return;
  }

  const token = authHeader.substring(7);

  // Service key bypass for headless/agent authentication
  // ⚠️ WARNING: Service key bypasses Row Level Security. Use only in trusted contexts.
  if (config.serviceKey && token.length === config.serviceKey.length) {
    if (timingSafeEqual(Buffer.from(token), Buffer.from(config.serviceKey))) {
      console.info(`[AUTH] Service key authentication from ${req.ip} ${req.path}`);
      req.auth = { userId: 'service_role', role: 'service_role' };
      next();
      return;
    }
  }

  try {
    const authInfo = await validateJWT(token);
    req.auth = authInfo;
    next();
  } catch (error) {
    console.error(error);
    res.status(401);
    res.setHeader(
      "WWW-Authenticate",
      `Bearer realm="mcp", resource_metadata="${config.mcpServerUrl}/.well-known/oauth-protected-resource", error="invalid_token"`
    );
    res.json({
      error: "invalid_token",
      error_description:
        error instanceof Error ? error.message : "Invalid token",
    });
  }
}
