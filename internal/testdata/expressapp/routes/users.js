const express = require("express");
const { supabase } = require("../lib/db");

const router = express.Router();

// PLANTED E4: cross-file router reads users by id with no auth check.
router.get("/:id", async (req, res) => {
  const { data } = await supabase.from("users").select("*").eq("id", req.params.id);
  res.json(data);
});

module.exports = router;
