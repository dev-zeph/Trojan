import { createClient } from "@/lib/supabase/server";

// SAFE #2: checks the signed-in user before reading.
export async function GET() {
  const supabase = createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) {
    return new Response("Unauthorized", { status: 401 });
  }
  const { data } = await supabase.from("profiles").select("*").eq("id", user.id);
  return Response.json(data);
}
