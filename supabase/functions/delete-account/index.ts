import Stripe from 'npm:stripe@17'
import { createClient } from 'npm:@supabase/supabase-js@2'
import { corsHeaders } from '../_shared/auth.ts'
import { supabase } from '../_shared/supabase.ts'

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response(null, { headers: corsHeaders() })
  if (req.method !== 'POST') return json({ error: 'Method not allowed' }, 405)

  const token = req.headers.get('authorization')?.replace('Bearer ', '')
  if (!token) return json({ error: 'Unauthorized' }, 401)

  // Verify the JWT directly — don't require a public.users row to exist
  const { data: { user: authUser }, error: authError } = await supabase.auth.getUser(token)
  if (authError || !authUser) return json({ error: 'Unauthorized' }, 401)

  const stripeKey = Deno.env.get('STRIPE_SECRET_KEY')
  const serviceRoleKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')
  const supabaseUrl = Deno.env.get('SUPABASE_URL')

  if (!serviceRoleKey || !supabaseUrl) return json({ error: 'Service misconfigured' }, 500)

  // Get subscription info from public.users — may not exist, that's fine
  const { data: userData } = await supabase
    .from('users')
    .select('subscription_id, stripe_customer_id')
    .eq('id', authUser.id)
    .single()

  // Cancel active Stripe subscription if present
  if (userData?.subscription_id && stripeKey) {
    try {
      const stripe = new Stripe(stripeKey)
      await stripe.subscriptions.cancel(userData.subscription_id)
    } catch {
      // Don't block deletion if Stripe cancel fails
    }
  }

  // Delete row from public.users (ignore if doesn't exist)
  await supabase.from('users').delete().eq('id', authUser.id)

  // Delete from auth.users — requires service role
  const adminClient = createClient(supabaseUrl, serviceRoleKey)
  const { error: deleteError } = await adminClient.auth.admin.deleteUser(authUser.id)

  if (deleteError) return json({ error: 'Failed to delete account' }, 500)

  return json({ deleted: true })
})

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...corsHeaders(), 'Content-Type': 'application/json' },
  })
}
