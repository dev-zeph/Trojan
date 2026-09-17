// Single conversion point between "we have a valid JWT" and "the app
// considers the user signed in".
//
// authStatus (not profile) is what every React gate in App.tsx reads (the
// Penetration Testing tab, Attack Market, lab upgrade prompts, ...). Before
// this module existed, that conversion was duplicated inline in three
// places -- app boot, the OAuth/deep-link callback, and (missing entirely)
// the first-run onboarding sign-in -- which is exactly how the "sign in
// twice" bug happened: onboarding persisted the profile but never derived
// authStatus from it, so every gate still read authStatus === null until the
// user signed in again.
//
// Every sign-in completion path MUST go through completeSignIn (directly or
// via App.tsx's applyAuthFromToken wrapper) so the whole app is satisfied by
// one sign-in.
import type { AuthStatus, UserProfile } from "../types";

export interface CompleteSignInDeps {
  decodeJWT: (token: string) => Record<string, unknown> | null;
  setAuthStatus: (status: AuthStatus) => void;
  refreshTokenBalance: () => void | Promise<void>;
}

// Decodes the token, derives AuthStatus, and applies it. No-ops (does not
// call setAuthStatus) if the token can't be decoded, matching the previous
// inline `try { ... } catch {}` behavior.
export function completeSignIn(token: string, email: string, deps: CompleteSignInDeps): void {
  let claims: Record<string, unknown> | null;
  try {
    claims = deps.decodeJWT(token);
  } catch {
    return;
  }
  if (!claims) return;
  const sub = (claims.subscription_status as string | undefined) ?? "";
  const status: AuthStatus = {
    loggedIn: true,
    isPro: sub === "pro" || sub === "team",
    plan: sub || "free",
    email,
  };
  deps.setAuthStatus(status);
  void deps.refreshTokenBalance();
}

export interface OnboardingCompleteDeps {
  setProfile: (p: UserProfile) => void;
  syncAuthToGoConfig: (token: string, email: string, refreshToken: string) => Promise<void>;
  applyAuthFromToken: (token: string, email: string) => void;
}

// Mirrors exactly what App.tsx's <Onboarding onDone> must do. Extracted so
// the wiring itself -- not just the token-decode math -- is unit-testable
// without rendering the 3000-line App component.
export async function onOnboardingDone(p: UserProfile, deps: OnboardingCompleteDeps): Promise<void> {
  deps.setProfile(p);
  if (p.token && p.email) {
    await deps.syncAuthToGoConfig(p.token, p.email, p.refreshToken ?? "");
    deps.applyAuthFromToken(p.token, p.email);
  }
}
