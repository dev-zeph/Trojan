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
