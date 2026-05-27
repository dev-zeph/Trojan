import { supabase } from '../_shared/supabase.ts'
import { validateToken, corsHeaders } from '../_shared/auth.ts'

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders() })
  }
  if (req.method !== 'POST') {
    return new Response(JSON.stringify({ error: 'Method not allowed' }), { status: 405 })
  }

  const token = req.headers.get('authorization')?.replace('Bearer ', '') ?? ''
  const user = await validateToken(token)
  if (!user) {
    return new Response(JSON.stringify({ error: 'Unauthorized' }), {
      status: 401,
      headers: corsHeaders(),
    })
  }

  // Only team owners can invite
  if (user.subscription_status !== 'team') {
    return new Response(JSON.stringify({ error: 'Team plan required' }), {
      status: 403,
      headers: corsHeaders(),
    })
  }

  const { email } = await req.json() as { email?: string }
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return new Response(JSON.stringify({ error: 'Valid email required' }), {
      status: 400,
      headers: corsHeaders(),
    })
  }

  // Look up the org this user owns
  const { data: org } = await supabase
    .from('organizations')
    .select('id, seat_limit')
    .eq('owner_id', user.id)
    .single()

  if (!org) {
    return new Response(JSON.stringify({ error: 'Organization not found' }), {
      status: 404,
      headers: corsHeaders(),
    })
  }

  // Count active + pending members (including the owner)
  const { count } = await supabase
    .from('org_members')
    .select('id', { count: 'exact', head: true })
    .eq('org_id', org.id)
    .in('status', ['active', 'pending'])

  if ((count ?? 0) >= org.seat_limit) {
    return new Response(
      JSON.stringify({ error: `Seat limit of ${org.seat_limit} reached` }),
      { status: 409, headers: corsHeaders() },
    )
  }

  // Insert pending invite (ignore conflict — already invited)
  const { error: insertError } = await supabase.from('org_members').insert({
    org_id: org.id,
    invited_email: email.toLowerCase(),
    role: 'member',
    status: 'pending',
  })

  if (insertError && insertError.code !== '23505') {
    // 23505 = unique violation (already invited — treat as success)
    return new Response(JSON.stringify({ error: 'Failed to create invite' }), {
      status: 500,
      headers: corsHeaders(),
    })
  }

  return new Response(JSON.stringify({ ok: true }), {
    headers: { ...corsHeaders(), 'Content-Type': 'application/json' },
  })
})
