const crypto = require("node:crypto");
const bcrypt = require("bcrypt");

function hashPassword(password) {
  // ruleid: trojan-js-weak-password-hash
  return crypto.createHash("sha256").update(password).digest("hex");
}

const verifyPassword = (input, stored) => {
  // ruleid: trojan-js-weak-password-hash
  return crypto.createHash("md5").update(input).digest("hex") === stored;
};

function register(req) {
  // ruleid: trojan-js-weak-password-hash
  const h = crypto.createHash("sha1").update(req.body.password).digest("hex");
  return h;
}

function fileChecksum(buf) {
  // ok: trojan-js-weak-password-hash
  return crypto.createHash("sha256").update(buf).digest("hex");
}

function etag(body) {
  // ok: trojan-js-weak-password-hash
  return crypto.createHash("md5").update(body).digest("base64");
}

async function hashPasswordGood(password) {
  // ok: trojan-js-weak-password-hash
  return bcrypt.hash(password, 12);
}

function resetTokenFor(user) {
  const minute = Math.floor(Date.now() / 60000);
  // ruleid: trojan-js-predictable-token
  return crypto.createHash("sha256").update(`${user.email}:${minute}`).digest("hex").slice(0, 24);
}

function makeInviteToken() {
  // ruleid: trojan-js-math-random-token
  return Math.random().toString(36).slice(2);
}

function shuffleCards(cards) {
  // ok: trojan-js-math-random-token
  return cards.sort(() => Math.random() - 0.5);
}

const createVerificationCode = () => {
  const seed = Date.now().toString();
  // ruleid: trojan-js-predictable-token
  return crypto.createHash("md5").update(seed).digest("hex");
};

function resetTokenGood() {
  // ok: trojan-js-predictable-token
  return crypto.randomBytes(32).toString("hex");
}

function auditLog(event) {
  // ok: trojan-js-predictable-token
  return crypto.createHash("sha256").update(`${event}:${Date.now()}`).digest("hex");
}

function tokenExpiry() {
  // ok: trojan-js-predictable-token
  const expires = Date.now() + 3600000;
  return crypto.randomBytes(16).toString("hex") + "." + String(expires).length;
}
