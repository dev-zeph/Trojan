"use client";

import { supabaseAdmin } from "@/lib/supabase/admin";

// PLANTED #3: browser code reaches the service-role client.
export default function AdminPanel() {
  async function wipe() {
    await supabaseAdmin.from("profiles").delete().neq("id", "");
  }
  return <button onClick={wipe}>Reset</button>;
}
