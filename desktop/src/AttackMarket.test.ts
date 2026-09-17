import { describe, expect, it } from "vitest";
import { attackMarketErrorMessage } from "./AttackMarket";

// Regression guard: 403 used to read "Attack Market is a Pro feature.", which
// is stale post-token-migration and actively wrong now that the
// attack-templates function's Pro gate is being removed -- a 403 there means
// a genuine permission problem, not a missing tier.
describe("attackMarketErrorMessage", () => {
  it("maps 401 to a sign-in prompt", () => {
    expect(attackMarketErrorMessage(401)).toMatch(/sign in/i);
  });

  it("maps 403 to a permission problem, not a Pro-tier upsell", () => {
    const msg = attackMarketErrorMessage(403);
    expect(msg).not.toMatch(/pro/i);
    expect(msg).toMatch(/permission/i);
  });

  it("maps 402 (insufficient tokens) to a top-up prompt", () => {
    const msg = attackMarketErrorMessage(402);
    expect(msg).toMatch(/token/i);
    expect(msg).toMatch(/top up/i);
  });

  it("falls back to a generic message for anything else", () => {
    expect(attackMarketErrorMessage(500)).toBe("Failed to load (500)");
  });
});
