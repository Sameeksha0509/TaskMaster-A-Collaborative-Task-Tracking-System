import bcrypt from "bcryptjs";
import jwt, { JwtPayload } from "jsonwebtoken";
import { randomUUID } from "node:crypto";
import { NextFunction, Request, Response } from "express";
import { prisma } from "./db";

function getSecret(): string {
  const value = process.env.JWT_SECRET;
  if (!value || value.length < 32) {
    throw new Error("JWT_SECRET must be set to at least 32 characters.");
  }
  return value;
}
const secret = getSecret();

const sessionDurationMs = 60 * 60 * 1000;

export async function createSession(userId: string): Promise<string> {
  const id = randomUUID();
  const expiresAt = new Date(Date.now() + sessionDurationMs);
  await prisma.session.create({ data: { id, userId, expiresAt } });
  return jwt.sign({ sub: userId, sid: id }, secret, {
    algorithm: "HS256",
    expiresIn: "1h"
  });
}

export async function requireAuth(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  const authorization = req.header("authorization");
  if (!authorization?.startsWith("Bearer ")) {
    res.status(401).json({ error: "Authentication required." });
    return;
  }

  let payload: JwtPayload;
  try {
    const verified = jwt.verify(authorization.slice(7), secret, { algorithms: ["HS256"] });
    if (typeof verified === "string") throw new Error("Invalid token payload.");
    payload = verified;
  } catch {
    res.status(401).json({ error: "Invalid or expired token." });
    return;
  }

  if (typeof payload.sub !== "string" || typeof payload.sid !== "string") {
    res.status(401).json({ error: "Invalid or expired token." });
    return;
  }

  const session = await prisma.session.findUnique({
    where: { id: payload.sid },
    select: { userId: true, expiresAt: true, revokedAt: true }
  });
  if (
    !session ||
    session.userId !== payload.sub ||
    session.revokedAt ||
    session.expiresAt <= new Date()
  ) {
    res.status(401).json({ error: "Invalid or expired session." });
    return;
  }
  req.userId = payload.sub;
  req.sessionId = payload.sid;
  next();
}
