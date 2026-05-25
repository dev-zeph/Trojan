import Stripe from 'npm:stripe@17'
import { validateToken, corsHeaders } from '../_shared/auth.ts'
import { supabase } from '../_shared/supabase.ts'

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response(null, { headers: corsHeaders() })
  if (req.method !== 'POST') return json({ error: 'Method not allowed' }, 405)

  const token = req.headers.get('authorization')?.replace('Bearer ', '')
  if (!token) return json({ error: 'Unauthorized' }, 401)

  const user = await validateToken(token)
  if (!user) return json({ error: 'Unauthorized' }, 401)

  const stripeKey = Deno.env.get('STRIPE_SECRET_KEY')
  if (!stripeKey) return json({ error: 'Service misconfigured' }, 500)

  const { data: userData } = await supabase
    .from('users')
    .select('stripe_customer_id')
    .eq('id', user.id)
    .single()

  if (!userData?.stripe_customer_id) {
    return json({ error: 'No active subscription found' }, 404)
  }

  const stripe = new Stripe(stripeKey)
  const body = await req.json().catch(() => ({}))
  const origin = body.origin ?? 'https://trojan.dev'

  const session = await stripe.billingPortal.sessions.create({
    customer: userData.stripe_customer_id,
    return_url: `${origin}/dashboard`,
  })

  return json({ url: session.url })
})

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...corsHeaders(), 'Content-Type': 'application/json' },
  })
}
