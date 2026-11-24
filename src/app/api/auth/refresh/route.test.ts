import { describe, expect, it, beforeEach, afterEach } from "vitest";
import { NextRequest } from "next/server";

import { AUTH_COOKIE_KEY, createSessionToken } from "@/lib/auth/session";
import {
  registerLoginFailure,
  resetLoginLockoutClock,
  resetLoginLockoutStore,
  setLoginLockoutClock,
} from "@/lib/auth/login-lockout";
import { POST } from "@/app/api/auth/refresh/route";
import { upsertUserWallet } from "@/lib/storage/user-wallet-store";
import { buildSecurityHeaders } from "@/lib/security/headers";

const WALLET = "GCDEFAULTTESTWALLET123";
const CLIENT_IP = "203.0.113.10";

function operatorCookie() {
  process.env.FORTEXA_AUTH_SECRET = "integration-test-secret";
  const token = createSessionToken({
    email: "operator@fortexa.local",
    role: "operator",
    userId: "refresh-operator",
    publicKey: WALLET,
    expiresInSeconds: 120,
  });

  return `${AUTH_COOKIE_KEY}=${token}`;
}

function refreshRequest() {
  return new NextRequest("http://localhost/api/auth/refresh", {
    method: "POST",
    headers: { cookie: operatorCookie(), "x-forwarded-for": CLIENT_IP },
  });
}

describe("/api/auth/refresh route", () => {
  beforeEach(async () => {
    process.env.FORTEXA_AUTH_MAX_ATTEMPTS = "1";
    process.env.FORTEXA_AUTH_LOCK_MINUTES = "1";
    resetLoginLockoutClock();
    await resetLoginLockoutStore();
  });

  afterEach(async () => {
    resetLoginLockoutClock();
    await resetLoginLockoutStore();
  });

  it("returns 401 when unauthenticated", async () => {
    const request = new NextRequest("http://localhost/api/auth/refresh", { method: "POST" });
    const response = await POST(request);

    expect(response.status).toBe(401);
    for (const [key, value] of Object.entries(buildSecurityHeaders())) {
      expect(response.headers.get(key)).toBe(value);
    }
  });

  it("returns 200 and rotates for authenticated user", async () => {
    await upsertUserWallet("refresh-operator", { publicKey: WALLET, source: "external" });
    const response = await POST(refreshRequest());
    expect(response.status).toBe(200);

    const payload = (await response.json()) as {
      ok: boolean;
      user: { userId: string; role: string };
    };

    expect(payload.ok).toBe(true);
    expect(payload.user.userId).toBe("refresh-operator");
    expect(payload.user.role).toBe("operator");

    for (const [key, value] of Object.entries(buildSecurityHeaders())) {
      expect(response.headers.get(key)).toBe(value);
    }
    expect(response.headers.get("Cache-Control")).toBe("no-store");
  });

  it("does not issue a session while the account is locked out", async () => {
    await upsertUserWallet("refresh-operator", { publicKey: WALLET, source: "external" });
    const start = Date.parse("2024-01-01T00:00:00.000Z");
    setLoginLockoutClock(() => start);
    await registerLoginFailure(WALLET, CLIENT_IP);

    const response = await POST(refreshRequest());
    expect(response.status).toBe(401);

    const payload = (await response.json()) as { error?: string; ok?: boolean };
    expect(payload.ok).toBeUndefined();
    expect(payload.error).toMatch(/locked/i);
    expect(response.cookies.get(AUTH_COOKIE_KEY)).toBeUndefined();
  });

  it("issues a session again after the lock expires", async () => {
    await upsertUserWallet("refresh-operator", { publicKey: WALLET, source: "external" });
    const start = Date.parse("2024-01-01T00:00:00.000Z");
    setLoginLockoutClock(() => start);
    await registerLoginFailure(WALLET, CLIENT_IP);

    setLoginLockoutClock(() => start + 60_000 + 1000);
    const response = await POST(refreshRequest());
    expect(response.status).toBe(200);

    const payload = (await response.json()) as {
      ok: boolean;
      user: { userId: string; role: string };
    };

    expect(payload.ok).toBe(true);
    expect(payload.user.userId).toBe("refresh-operator");
  });
});
