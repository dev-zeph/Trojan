import { createClient } from "@/lib/supabase/server";

// PLANTED #1: writes to orders with no auth check.
export async function POST(req: Request) {
  const body = await req.json();
  const supabase = createClient();
  const { data, error } = await supabase.from("orders").insert(body);
  return Response.json({ data, error });
}
