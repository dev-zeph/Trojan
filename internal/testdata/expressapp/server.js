const express = require("express");
const { supabase, pool } = require("./lib/db");
const { requireAuth } = require("./middleware/auth");
const usersRouter = require("./routes/users");

const app = express();
app.use(express.json());

app.get("/health", (req, res) => res.send("ok"));

// SAFE E1: protected by requireAuth.
app.post("/api/notes", requireAuth, async (req, res) => {
  const { data } = await supabase.from("notes").insert({ body: req.body.body, user_id: req.user.id });
  res.json(data);
});

// PLANTED E2: deletes with no auth check.
app.delete("/api/notes/:id", async (req, res) => {
  await supabase.from("notes").delete().eq("id", req.params.id);
  res.sendStatus(204);
});

// PLANTED E3: raw SQL from a query parameter.
app.get("/api/search", async (req, res) => {
  const result = await pool.query("SELECT * FROM notes WHERE body LIKE '%" + req.query.q + "%'");
  res.json(result.rows);
});

app.use("/api/users", usersRouter);

app.listen(3000);
