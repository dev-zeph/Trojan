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

  return data as User | null
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
