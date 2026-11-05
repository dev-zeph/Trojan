import { getDb } from "@/lib/db";

const columns = ["id", "name", "created_at"];

// SAFE S5: interpolates a constant column list, nothing from the request.
export async function GET() {
  const rows = getDb().prepare(`SELECT ${columns.join(", ")} FROM products ORDER BY id`).all();
  return Response.json(rows);
}
