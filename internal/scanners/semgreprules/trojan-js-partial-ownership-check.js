const db = require("./db");

// Direct shape: ids[0] checked at top level, whole array queried after.
function exportInvoices(req, res) {
  const ids = (Array.isArray(req.body.ids) ? req.body.ids : []).map(Number);
  const first = db.prepare("SELECT client_id FROM invoices WHERE id = ?").get(ids[0]);
  if (!first || first.client_id !== req.user.client_id) return res.sendStatus(403);
  const marks = ids.map(() => "?").join(",");
  // ruleid: trojan-js-partial-ownership-check
  const rows = db.prepare(`SELECT * FROM invoices WHERE id IN (${marks})`).all(...ids);
  res.json(rows);
}

// If-wrapped shape (as planted in ashgrove): ids[0] checked inside an if,
// whole array queried in the outer body.
function exportScoped(req, res) {
  const ids = (Array.isArray(req.body.ids) ? req.body.ids : []).map(Number);
  const scope = req.user.client_id;
  if (scope !== null) {
    const first = db.prepare("SELECT client_id FROM invoices WHERE id = ?").get(ids[0]);
    if (!first || first.client_id !== scope) return res.sendStatus(403);
  }
  const marks = ids.map(() => "?").join(",");
  // ruleid: trojan-js-partial-ownership-check
  const rows = db.prepare(`SELECT * FROM invoices WHERE id IN (${marks})`).all(...ids);
  res.json(rows);
}

// clean: ownership scoped for the whole set in the same query, not just ids[0].
function exportChecked(req, res) {
  const ids = (Array.isArray(req.body.ids) ? req.body.ids : []).map(Number);
  const marks = ids.map(() => "?").join(",");
  // ok: trojan-js-partial-ownership-check
  const rows = db
    .prepare(`SELECT * FROM invoices WHERE id IN (${marks}) AND client_id = ?`)
    .all(...ids, req.user.client_id);
  res.json(rows);
}

// clean: single record, ids[0] checked and ids[0] is the only thing read.
function singleInvoice(req, res) {
  const ids = [Number(req.params.id)];
  // ok: trojan-js-partial-ownership-check
  const row = db.prepare("SELECT * FROM invoices WHERE id = ?").get(ids[0]);
  if (!row || row.client_id !== req.user.client_id) return res.sendStatus(403);
  res.json(row);
}
