import { describe, expect, it, vi } from "vitest";
import { completeSignIn, onOnboardingDone } from "./auth";
import type { UserProfile, AuthStatus } from "../types";

describe("completeSignIn", () => {
  it("derives loggedIn AuthStatus from a decodable JWT and refreshes the balance", () => {
    const setAuthStatus = vi.fn();
    const refreshTokenBalance = vi.fn();
    const decodeJWT = vi.fn().mockReturnValue({ subscription_status: "pro" });

    completeSignIn("tok", "user@example.com", { decodeJWT, setAuthStatus, refreshTokenBalance });

    expect(setAuthStatus).toHaveBeenCalledWith({
      loggedIn: true,
      isPro: true,
      plan: "pro",
      email: "user@example.com",
    } satisfies AuthStatus);
    expect(refreshTokenBalance).toHaveBeenCalledTimes(1);
  });

  it("does nothing if the token can't be decoded", () => {
    const setAuthStatus = vi.fn();
    const refreshTokenBalance = vi.fn();
    const decodeJWT = vi.fn().mockReturnValue(null);

    completeSignIn("bad-token", "user@example.com", { decodeJWT, setAuthStatus, refreshTokenBalance });

    expect(setAuthStatus).not.toHaveBeenCalled();
    expect(refreshTokenBalance).not.toHaveBeenCalled();
  });
});

describe("onOnboardingDone (regression guard for the double sign-in bug)", () => {
  // Bug: the first-run onboarding sign-in persisted `profile` but never
  // derived in-memory `authStatus`, which every gate in the app actually
  // reads (e.g. the Penetration Testing tab's `authStatus?.loggedIn`). The
  // user had to sign in a second time to make that gate open. This test
  // asserts the fixed contract: after onboarding completes with a token,
  // applyAuthFromToken MUST be called so authStatus.loggedIn ends up true.
  it("calls applyAuthFromToken so the pen-test gate would open after a single sign-in", async () => {
    const setProfile = vi.fn();
    const syncAuthToGoConfig = vi.fn().mockResolvedValue(undefined);
    const applyAuthFromToken = vi.fn();

    const profile: UserProfile = { name: "Ada", email: "ada@example.com", token: "jwt", refreshToken: "r" };

    await onOnboardingDone(profile, { setProfile, syncAuthToGoConfig, applyAuthFromToken });

    expect(setProfile).toHaveBeenCalledWith(profile);
    expect(syncAuthToGoConfig).toHaveBeenCalledWith("jwt", "ada@example.com", "r");
    expect(applyAuthFromToken).toHaveBeenCalledWith("jwt", "ada@example.com");
  });

  it("does not call applyAuthFromToken when there is no token (local/no-account profile)", async () => {
    const setProfile = vi.fn();
    const syncAuthToGoConfig = vi.fn().mockResolvedValue(undefined);
    const applyAuthFromToken = vi.fn();

    const profile: UserProfile = { name: "Local User", email: "" };

    await onOnboardingDone(profile, { setProfile, syncAuthToGoConfig, applyAuthFromToken });

    expect(setProfile).toHaveBeenCalledWith(profile);
    expect(syncAuthToGoConfig).not.toHaveBeenCalled();
    expect(applyAuthFromToken).not.toHaveBeenCalled();
  });
});
