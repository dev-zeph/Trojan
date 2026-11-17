const express = require("express");
const router = express.Router();

// The ashgrove /api/quote case: attacker-controlled field NAMES become the
// generated function's parameter list.
router.post("/quote", (req, res) => {
  const inputs = req.body.inputs && typeof req.body.inputs === "object" ? req.body.inputs : {};
  const names = Object.keys(inputs);
  const values = names.map((n) => Number(inputs[n]) || 0);
  // ruleid: trojan-js-dynamic-code-exec
  const estimate = new Function(...names, `return (${card.formula});`);
  res.json({ total: estimate(...values) });
});

router.post("/eval", (req, res) => {
  // ruleid: trojan-js-dynamic-code-exec
  const out = eval(req.body.expr);
  res.json({ out });
});

router.get("/run", (req, res) => {
  // ruleid: trojan-js-dynamic-code-exec
  const fn = Function("return " + req.query.code);
  res.json({ out: fn() });
});

router.post("/calc", (req, res) => {
  const formula = req.body.formula;
  // ruleid: trojan-js-dynamic-code-exec
  const f = new Function("x", "y", formula);
  res.json({ out: f(1, 2) });
});

router.post("/safe", (req, res) => {
  // ok: trojan-js-dynamic-code-exec
  const add = new Function("a", "b", "return a + b");
  res.json({ out: add(2, 3) });
});

router.get("/parse", (req, res) => {
  // ok: trojan-js-dynamic-code-exec
  const n = eval("1 + 2");
  res.json({ n });
});
