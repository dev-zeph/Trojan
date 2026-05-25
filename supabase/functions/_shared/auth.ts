import { supabase } from './supabase.ts'
import type { User } from './supabase.ts'

export async function validateToken(token: string): Promise<User | null> {
  const { data: { user }, error } = await supabase.auth.getUser(token)
  if (error || !user) return null

  const { data } = await supabase
    .from('users')
    .select('*')
    .eq('id', user.id)
    .single()

  if (data) return data as User

  // Row missing — create it with free defaults so the user isn't locked out
  const newUser = {
    id: user.id,
    email: user.email ?? '',
    github_username: user.user_metadata?.user_name ?? null,
    stripe_customer_id: null,
    subscription_status: 'free' as const,
    subscription_id: null,
  }
  await supabase.from('users').upsert(newUser, { onConflict: 'id' })
  return { ...newUser, created_at: new Date().toISOString() }
}

export function isPro(user: User): boolean {
  return user.subscription_status === 'pro' || user.subscription_status === 'team'
}

export function corsHeaders(origin = '*') {
  return {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Headers': 'authorization, content-type',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
  }
}
