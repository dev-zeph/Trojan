import { createClient } from '@supabase/supabase-js'

const supabaseUrl = process.env['SUPABASE_URL']
const supabaseServiceKey = process.env['SUPABASE_SERVICE_ROLE_KEY']

if (!supabaseUrl || !supabaseServiceKey) {
  throw new Error('Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY environment variables')
}

// Service role client — has full DB access, only used server-side
export const supabase = createClient(supabaseUrl, supabaseServiceKey)

// Database types
export interface User {
  id: string
  email: string
  github_username: string
  stripe_customer_id: string | null
  subscription_status: 'free' | 'pro' | 'team'
  subscription_id: string | null
  created_at: string
}

export interface AiCache {
  id: string
  rule_id: string
  scanner: string
  simply: string
  actions: string[]
  created_at: string
}
