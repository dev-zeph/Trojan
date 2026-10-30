import { createServerClient } from "@supabase/ssr";
import { cookies } from "next/headers";

// Shared helper used by several routes (exercises cross-file resolution).
export function createClient() {
  const store = cookies();
  return createServerClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
    { cookies: { getAll: () => store.getAll() } }
  );
}
