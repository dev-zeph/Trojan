const crypto = require("node:crypto");
const jwt = require("jsonwebtoken");
const session = require("express-session");

// ruleid: trojan-js-secret-fallback
const secret = process.env.SESSION_SECRET || ["meridian", "portal", "2024"].join("-");

// ruleid: trojan-js-secret-fallback
const jwtKey = process.env.JWT_SECRET ?? "dev-secret-change-me";

// ruleid: trojan-js-secret-fallback
const apiKey = process.env["STRIPE_API_KEY"] || "sk_test_123456789";

// ruleid: trojan-js-secret-fallback
const salt = process.env.PASSWORD_SALT || `static-salt`;

// ok: trojan-js-secret-fallback
const fromOther = process.env.SESSION_SECRET || process.env.LEGACY_SECRET;

// ok: trojan-js-secret-fallback
const failsClosed = process.env.SESSION_SECRET || "";

// ok: trojan-js-secret-fallback
const random = process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex");

// ok: trojan-js-secret-fallback
const port = process.env.PORT || "3000";

// ok: trojan-js-secret-fallback
const region = process.env.AWS_REGION || "us-east-1";

function sign(v) {
  // ruleid: trojan-js-hardcoded-signing-key
  return crypto.createHmac("sha256", "super-secret").update(v).digest("hex");
}

function signOk(v) {
  // ok: trojan-js-hardcoded-signing-key
  return crypto.createHmac("sha256", secret).update(v).digest("hex");
}

// ruleid: trojan-js-hardcoded-signing-key
const t = jwt.sign({ sub: 1 }, "keyboard cat", { expiresIn: "1h" });

// ok: trojan-js-hardcoded-signing-key
const t2 = jwt.sign({ sub: 1 }, jwtKey);

// ruleid: trojan-js-hardcoded-signing-key
app.use(session({ secret: "keyboard cat", resave: false }));

// ok: trojan-js-hardcoded-signing-key
app.use(session({ secret: process.env.SESSION_SECRET, resave: false }));
