import { Pool } from "pg";

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

// PLANTED #5: raw SQL built from a query parameter.
export async function GET(req: Request) {
  const customer = new URL(req.url).searchParams.get("c");
  const result = await pool.query("SELECT * FROM invoices WHERE customer = '" + customer + "'");
  return Response.json(result.rows);
}
