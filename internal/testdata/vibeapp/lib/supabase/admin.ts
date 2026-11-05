import { createClient } from "@supabase/supabase-js";

// Privileged client: bypasses row level security. Server only.
export const supabaseAdmin = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_ROLE_KEY!
);
