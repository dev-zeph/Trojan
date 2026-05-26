import Stripe from 'npm:stripe@17'
import { validateToken, corsHeaders } from '../_shared/auth.ts'
import { supabase } from '../_shared/supabase.ts'

const PLANS = {
  pro_monthly: { priceId: Deno.env.get('STRIPE_PRO_MONTHLY_PRICE_ID') ?? '' },
  pro_yearly:  { priceId: Deno.env.get('STRIPE_PRO_YEARLY_PRICE_ID') ?? '' },
} as const

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response(null, { headers: corsHeaders() })
  if (req.method !== 'POST') return json({ error: 'Method not allowed' }, 405)

  const token = req.headers.get('authorization')?.replace('Bearer ', '')
  if (!token) return json({ error: 'Unauthorized' }, 401)

  const user = await validateToken(token)
  if (!user) return json({ error: 'Unauthorized' }, 401)

  const stripeKey = Deno.env.get('STRIPE_SECRET_KEY')
  if (!stripeKey) return json({ error: 'Service misconfigured' }, 500)

  const body = await req.json()
  const plan = PLANS[body.plan as keyof typeof PLANS]
  if (!plan) return json({ error: 'Invalid plan' }, 400)

  const origin = body.origin ?? 'https://trojancli.com'
  const stripe = new Stripe(stripeKey)

  const { data: profile } = await supabase
    .from('users')
    .select('stripe_customer_id')
    .eq('id', user.id)
    .single()

  const session = await stripe.checkout.sessions.create({
    ui_mode: 'embedded',
    mode: 'subscription',
    payment_method_types: ['card'],
    line_items: [{ price: plan.priceId, quantity: 1 }],
    ...(profile?.stripe_customer_id
      ? { customer: profile.stripe_customer_id }
      : { customer_email: user.email }),
    return_url: `${origin}/checkout/complete?session_id={CHECKOUT_SESSION_ID}`,
    metadata: { userId: user.id, plan: body.plan },
  })

  return json({ clientSecret: session.client_secret })
})

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...corsHeaders(), 'Content-Type': 'application/json' },
  })
}
