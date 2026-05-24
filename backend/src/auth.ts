import { supabase } from './supabase.ts'
import type { User } from './supabase.ts'

// Validate an API token from the CLI and return the user.
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

// Check if a user has an active paid subscription.
export function isPro(user: User): boolean {
  return user.subscription_status === 'pro' || user.subscription_status === 'team'
}

// Get the platform Anthropic API key.
export function getAnthropicKey(): string {
  const platformKey = process.env['ANTHROPIC_API_KEY']
  if (!platformKey) throw new Error('No Anthropic API key configured')
  return platformKey
}
