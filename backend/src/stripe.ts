import Stripe from 'stripe'

const stripeKey = process.env['STRIPE_SECRET_KEY']
if (!stripeKey) throw new Error('Missing STRIPE_SECRET_KEY')

export const stripe = new Stripe(stripeKey)

export const PLANS = {
  pro: {
    name: 'Pro',
    priceId: process.env['STRIPE_PRO_PRICE_ID'] ?? '',
    amount: 1500, // $15.00
  },
  pro_byok: {
    name: 'Pro (BYOK)',
    priceId: process.env['STRIPE_PRO_BYOK_PRICE_ID'] ?? '',
    amount: 500, // $5.00
  },
  team: {
    name: 'Team',
    priceId: process.env['STRIPE_TEAM_PRICE_ID'] ?? '',
    amount: 9900, // $99.00
  },
} as const

export type PlanKey = keyof typeof PLANS
