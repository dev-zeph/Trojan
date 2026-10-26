import pkg from "../package.json";
// App-wide constants.
// SUPABASE_URL previously existed as separate literals in App.tsx and
// AttackMarket.tsx; both now import it from here.

export const STORE_KEY    = "recent-projects";
export const PROFILE_KEY  = "user-profile";
export const TERMINAL_KEY = "terminal-prefs";

export const SUPABASE_URL      = "https://dtmocojzvgsswjdsrmqr.supabase.co";
export const SUPABASE_ANON_KEY = "sb_publishable_U1qvJb7QebxgH5_0HCMYJQ_jKBybATQ";

// Public site. Checkout is embedded Stripe (ui_mode: "embedded"), which needs
// Stripe.js in a real browser page, so the desktop app hands billing off to
// the website rather than trying to mount it inside the webview.
export const MARKETING_URL = "https://trojancli.com";

// Shipped version, surfaced in the sidebar and attached to every feedback
// report. The sidebar hardcoded "v0.1" through five releases, which would have
// made tester reports point at the wrong build.
// Read from package.json so it can't fall out of step (it said 0.3.0 in the
// 0.3.1 release). Keep package.json and src-tauri/tauri.conf.json in step.
export const APP_VERSION: string = pkg.version;
