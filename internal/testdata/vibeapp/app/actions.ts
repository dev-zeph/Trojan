"use server";

import { createClient } from "@/lib/supabase/server";

// PLANTED #4: server action deletes with no auth check.
export async function deletePost(id: string) {
  const supabase = createClient();
  await supabase.from("posts").delete().eq("id", id);
}
