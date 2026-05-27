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
    const rawPlan = session.metadata?.['plan'] ?? ''
    const isTeam = rawPlan.startsWith('team')
    const plan = isTeam ? 'team' : 'pro'

    if (userId) {
      await supabase.from('users').update({
        subscription_status: plan,
        subscription_id: session.subscription,
        stripe_customer_id: session.customer,
      }).eq('id', userId)

      // For team plans: create the organization and add the owner as an active member
      if (isTeam) {
        const seatLimit = rawPlan.startsWith('team_10') ? 10 : 5

        // Fetch owner email for the org_members row
        const { data: owner } = await supabase
          .from('users')
          .select('email')
          .eq('id', userId)
          .single()

        const { data: org } = await supabase
          .from('organizations')
          .insert({
            owner_id: userId,
            stripe_customer_id: session.customer as string,
            subscription_id: session.subscription as string,
            seat_limit: seatLimit,
          })
          .select('id')
          .single()

        if (org && owner) {
          await supabase.from('org_members').upsert({
            org_id: org.id,
            user_id: userId,
            invited_email: owner.email,
            role: 'owner',
            status: 'active',
            joined_at: new Date().toISOString(),
          }, { onConflict: 'org_id,invited_email' })
        }
      }
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

    // Reset the owner's subscription
    const { data: owner } = await supabase
      .from('users')
      .update({ subscription_status: 'free', subscription_id: null })
      .eq('subscription_id', sub.id)
      .select('id')
      .single()

    // Deactivate all org members so they lose pro access immediately
    if (owner) {
      const { data: org } = await supabase
        .from('organizations')
        .select('id')
        .eq('owner_id', owner.id)
        .single()

      if (org) {
        await supabase
          .from('org_members')
          .update({ status: 'pending' })
          .eq('org_id', org.id)
          .eq('role', 'member')
      }
    }
  }

  return new Response(JSON.stringify({ received: true }), {
    headers: { 'Content-Type': 'application/json' },
  })
})
