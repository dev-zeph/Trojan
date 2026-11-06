const express = require("express");
const app = express();
const router = express.Router();

router.get("/invoices/:id", (req, res) => {
  // ruleid: trojan-js-request-overrides-session-identity
  const clientId = Number(req.query.client ?? req.user.clientId);
  res.json(db.get(req.params.id, clientId));
});

router.get("/orders", (req, res) => {
  // ruleid: trojan-js-request-overrides-session-identity
  const owner = req.body.userId || req.session.userId;
  res.json(db.orders(owner));
});

router.get("/me", (req, res) => {
  // ok: trojan-js-request-overrides-session-identity
  const owner = req.user.id;
  // ok: trojan-js-request-overrides-session-identity
  const page = req.query.page || 1;
  res.json(db.orders(owner, page));
});

router.patch("/profile", (req, res) => {
  const { password, currentPassword, ...changes } = req.body || {};
  if (password) changes.password_hash = hash(password);
  // ruleid: trojan-js-mass-assignment
  const updated = updateRow("users", req.user.id, changes);
  res.json(updated);
});

router.put("/users/:id", async (req, res) => {
  // ruleid: trojan-js-mass-assignment
  await User.findByIdAndUpdate(req.params.id, req.body);
  // ruleid: trojan-js-mass-assignment
  Object.assign(req.user, req.body);
  // ruleid: trojan-js-mass-assignment
  await prisma.user.update({ where: { id: 1 }, data: { ...req.body } });
  res.sendStatus(204);
});

router.patch("/settings", async (req, res) => {
  const { name, phone } = req.body;
  // ok: trojan-js-mass-assignment
  await updateRow("users", req.user.id, { name, phone });
  // ok: trojan-js-mass-assignment
  await prisma.user.update({ where: { id: 1 }, data: { name: req.body.name } });
  res.sendStatus(204);
});

app.use((req, res, next) => {
  // ruleid: trojan-js-case-sensitive-path-check
  if (req.path.startsWith("/admin") && req.user?.role !== "admin") {
    return res.status(403).send("Partners only");
  }
  next();
});

app.use(function (req, res, next) {
  // ruleid: trojan-js-case-sensitive-path-check
  if (req.url.indexOf("/dashboard") === 0 && !req.user) {
    return res.redirect("/login");
  }
  next();
});

app.use((req, res, next) => {
  // ok: trojan-js-case-sensitive-path-check
  if (req.path.startsWith("/api")) {
    res.set("Cache-Control", "no-store");
  }
  next();
});

app.use((req, res, next) => {
  // ok: trojan-js-case-sensitive-path-check
  if (req.path.toLowerCase().startsWith("/admin") && !req.user) {
    return res.status(403).send("no");
  }
  next();
});
