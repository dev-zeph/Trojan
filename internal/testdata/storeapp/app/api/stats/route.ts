import { sql } from "@vercel/postgres";
import { getDb } from "@/lib/db";

// SAFE S4: @vercel/postgres tagged template, and a tagged template handed to
// a query method (drizzle-style db.execute(sql`...`)).
export async function GET(req: Request) {
  const day = new URL(req.url).searchParams.get("day");
  const { rows } = await sql`SELECT count(*) FROM orders WHERE day = ${day}`;
  await getDb().execute(sql`SELECT * FROM orders WHERE day = ${day}`);
  return Response.json(rows);
}
