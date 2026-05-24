import { createClient } from 'npm:@supabase/supabase-js@2'

// SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are automatically injected
// by the Supabase runtime — no need to set them in the dashboard.
export const supabase = createClient(
  Deno.env.get('SUPABASE_URL')!,
  Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!,
)

export interface User {
  id: string
  email: string
  github_username: string | null
  stripe_customer_id: string | null
  subscription_status: 'free' | 'pro' | 'team'
  subscription_id: string | null
  created_at: string
}
