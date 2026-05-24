import { createServer } from 'node:http'
import { validateToken, isPro, getAnthropicKey } from './auth.ts'
import { synthesize } from './synthesize.ts'
import { stripe, PLANS } from './stripe.ts'
import { supabase } from './supabase.ts'

const PORT = Number(process.env['PORT'] ?? 3001)

// Minimal HTTP server — no framework needed for this surface area
const server = createServer(async (req, res) => {
  const url = new URL(req.url ?? '/', `http://localhost:${PORT}`)

  res.setHeader('Content-Type', 'application/json')

  // Health check
  if (url.pathname === '/health' && req.method === 'GET') {
    res.end(JSON.stringify({ ok: true }))
    return
  }

  // POST /api/synthesize — AI explanation for a finding
  if (url.pathname === '/api/synthesize' && req.method === 'POST') {
    const token = req.headers['authorization']?.replace('Bearer ', '')
    if (!token) { res.statusCode = 401; res.end(JSON.stringify({ error: 'Unauthorized' })); return }

    const user = await validateToken(token)
    if (!user || !isPro(user)) { res.statusCode = 403; res.end(JSON.stringify({ error: 'Pro subscription required' })); return }

    const body = await readBody(req)
    const finding = JSON.parse(body)
    const key = getAnthropicKey()
    const result = await synthesize(finding, key)

    res.end(JSON.stringify(result))
    return
  }

  // POST /api/checkout — create Stripe checkout session
  if (url.pathname === '/api/checkout' && req.method === 'POST') {
    const token = req.headers['authorization']?.replace('Bearer ', '')
    if (!token) { res.statusCode = 401; res.end(JSON.stringify({ error: 'Unauthorized' })); return }

    const user = await validateToken(token)
    if (!user) { res.statusCode = 401; res.end(JSON.stringify({ error: 'Unauthorized' })); return }

    const body = JSON.parse(await readBody(req))
    const plan = PLANS[body.plan as keyof typeof PLANS]
    if (!plan) { res.statusCode = 400; res.end(JSON.stringify({ error: 'Invalid plan' })); return }

    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      payment_method_types: ['card'],
      line_items: [{ price: plan.priceId, quantity: 1 }],
      customer_email: user.email,
      success_url: 'https://trojan.dev/dashboard?success=1',
      cancel_url: 'https://trojan.dev/pricing',
      metadata: { userId: user.id },
    })

    res.end(JSON.stringify({ url: session.url }))
    return
  }

  // POST /api/webhooks/stripe — handle Stripe events
  if (url.pathname === '/api/webhooks/stripe' && req.method === 'POST') {
    const sig = req.headers['stripe-signature'] as string
    const webhookSecret = process.env['STRIPE_WEBHOOK_SECRET'] ?? ''
    const body = await readBodyRaw(req)

    let event
    try {
      event = stripe.webhooks.constructEvent(body, sig, webhookSecret)
    } catch {
      res.statusCode = 400
      res.end(JSON.stringify({ error: 'Invalid signature' }))
      return
    }

    if (event.type === 'checkout.session.completed') {
      const session = event.data.object
      const userId = session.metadata?.['userId']
      if (userId) {
        await supabase.from('users').update({
          subscription_status: 'pro',
          subscription_id: session.subscription,
          stripe_customer_id: session.customer,
        }).eq('id', userId)
      }
    }

    if (event.type === 'customer.subscription.deleted') {
      const sub = event.data.object
      await supabase.from('users')
        .update({ subscription_status: 'free', subscription_id: null })
        .eq('subscription_id', sub.id)
    }

    res.end(JSON.stringify({ received: true }))
    return
  }

  res.statusCode = 404
  res.end(JSON.stringify({ error: 'Not found' }))
})

server.listen(PORT, () => {
  console.log(`Trojan backend running on port ${PORT}`)
})

function readBody(req: Parameters<typeof createServer>[0] extends (...args: infer P) => unknown ? P[0] : never): Promise<string> {
  return new Promise((resolve, reject) => {
    let body = ''
    req.on('data', chunk => { body += chunk })
    req.on('end', () => resolve(body))
    req.on('error', reject)
  })
}

function readBodyRaw(req: Parameters<typeof createServer>[0] extends (...args: infer P) => unknown ? P[0] : never): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = []
    req.on('data', chunk => chunks.push(chunk as Buffer))
    req.on('end', () => resolve(Buffer.concat(chunks)))
    req.on('error', reject)
  })
}
