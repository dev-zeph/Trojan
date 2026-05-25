import Stripe from 'npm:stripe@17'
import { supabase } from '../_shared/supabase.ts'

Deno.serve(async (req) => {
  if (req.method !== 'POST') {
    return new Response(JSON.stringify({ error: 'Method not allowed' }), { status: 405 })
  }

  const stripeKey = Deno.env.get('STRIPE_SECRET_KEY')
  const webhookSecret = Deno.env.get('STRIPE_WEBHOOK_SECRET')
  if (!stripeKey || !webhookSecret) {
    return new Response(JSON.stringify({ error: 'Service misconfigured' }), { status: 500 })
  }

  const stripe = new Stripe(stripeKey)
  const sig = req.headers.get('stripe-signature') ?? ''
  const body = await req.text()

  let event: Stripe.Event
  try {
    event = await stripe.webhooks.constructEventAsync(body, sig, webhookSecret)
  } catch {
    return new Response(JSON.stringify({ error: 'Invalid signature' }), { status: 400 })
  }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object as Stripe.Checkout.Session
    const userId = session.metadata?.['userId']
    const plan = (session.metadata?.['plan'] === 'team') ? 'team' : 'pro'
    if (userId) {
      await supabase.from('users').update({
        subscription_status: plan,
        subscription_id: session.subscription,
        stripe_customer_id: session.customer,
      }).eq('id', userId)
    }
  }

  if (event.type === 'customer.subscription.updated') {
    const sub = event.data.object as Stripe.Subscription
    if (sub.status === 'active') {
      // Keep whatever plan they already have (pro/team); just ensure it's not free
      const { data: existing } = await supabase
        .from('users')
        .select('subscription_status')
        .eq('subscription_id', sub.id)
        .single()
      const currentStatus = existing?.subscription_status
      if (currentStatus === 'free' || !currentStatus) {
        await supabase.from('users')
          .update({ subscription_status: 'pro' })
          .eq('subscription_id', sub.id)
      }
    } else {
      await supabase.from('users')
        .update({ subscription_status: 'free' })
        .eq('subscription_id', sub.id)
    }
  }

  if (event.type === 'customer.subscription.deleted') {
    const sub = event.data.object as Stripe.Subscription
    await supabase.from('users')
      .update({ subscription_status: 'free', subscription_id: null })
      .eq('subscription_id', sub.id)
  }

  return new Response(JSON.stringify({ received: true }), {
    headers: { 'Content-Type': 'application/json' },
  })
})
