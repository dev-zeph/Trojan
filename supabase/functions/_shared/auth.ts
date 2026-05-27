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

  let profile: User

  if (data) {
    profile = data as User
  } else {
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
    profile = { ...newUser, created_at: new Date().toISOString(), is_team_member: false }
    return profile
  }

  // For free-tier users, check if they're an active member of a team org.
  // Team owners already have subscription_status === 'team', so skip the lookup for them.
  let is_team_member = false
  if (profile.subscription_status === 'free') {
    const { data: membership } = await supabase
      .from('org_members')
      .select('id')
      .eq('user_id', user.id)
      .eq('status', 'active')
      .limit(1)
      .single()
    is_team_member = !!membership
  }

  return { ...profile, is_team_member }
}

export function isPro(user: User): boolean {
  return (
    user.subscription_status === 'pro' ||
    user.subscription_status === 'team' ||
    user.is_team_member === true
  )
}

export function corsHeaders(origin = '*') {
  return {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Headers': 'authorization, content-type',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
  }
}
