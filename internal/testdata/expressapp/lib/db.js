const { createClient } = require("@supabase/supabase-js");
const { Pool } = require("pg");

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

module.exports = { supabase, pool };
