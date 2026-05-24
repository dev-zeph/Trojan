import { validateToken, isPro, corsHeaders } from '../_shared/auth.ts'

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders() })
  }

  if (req.method !== 'GET') {
    return json({ error: 'Method not allowed' }, 405)
  }

  const token = req.headers.get('authorization')?.replace('Bearer ', '')
  if (!token) return json({ error: 'Unauthorized' }, 401)

  const user = await validateToken(token)
  if (!user) return json({ error: 'Unauthorized' }, 401)

  return json({
    isPro: isPro(user),
    subscriptionStatus: user.subscription_status,
    email: user.email,
  })
})

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...corsHeaders(), 'Content-Type': 'application/json' },
  })
}
