import Stripe from 'npm:stripe@17'
import { validateToken, corsHeaders } from '../_shared/auth.ts'

const PLANS = {
  pro: {
    priceId: Deno.env.get('STRIPE_PRO_PRICE_ID') ?? '',
  },
  team: {
    priceId: Deno.env.get('STRIPE_TEAM_PRICE_ID') ?? '',
  },
} as const

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders() })
  }

  if (req.method !== 'POST') {
    return json({ error: 'Method not allowed' }, 405)
  }

  const token = req.headers.get('authorization')?.replace('Bearer ', '')
  if (!token) return json({ error: 'Unauthorized' }, 401)

  const user = await validateToken(token)
  if (!user) return json({ error: 'Unauthorized' }, 401)

  const stripeKey = Deno.env.get('STRIPE_SECRET_KEY')
  if (!stripeKey) return json({ error: 'Service misconfigured' }, 500)

  const stripe = new Stripe(stripeKey)
  const body = await req.json()
  const plan = PLANS[body.plan as keyof typeof PLANS]

  if (!plan) return json({ error: 'Invalid plan' }, 400)

  const session = await stripe.checkout.sessions.create({
    mode: 'subscription',
    payment_method_types: ['card'],
    line_items: [{ price: plan.priceId, quantity: 1 }],
    customer_email: user.email,
    success_url: 'https://trojan.dev/dashboard?success=1',
    cancel_url: 'https://trojan.dev/pricing',
    metadata: { userId: user.id },
  })

  return json({ url: session.url })
})

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...corsHeaders(), 'Content-Type': 'application/json' },
  })
}
