import postgres from "postgres";

const sql = postgres(process.env.DATABASE_URL ?? "");

// SAFE S3: postgres.js tagged template binds ${q} as a parameter.
export async function GET(req: Request) {
  const q = new URL(req.url).searchParams.get("q") ?? "";
  const rows = await sql`SELECT * FROM products WHERE name = ${q}`;
  return Response.json(rows);
}
