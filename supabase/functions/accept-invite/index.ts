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

  // Find a pending invite for this user's email
  const { data: invite } = await supabase
    .from('org_members')
    .select('id')
    .eq('invited_email', user.email.toLowerCase())
    .eq('status', 'pending')
    .limit(1)
    .single()

  if (!invite) {
    return new Response(JSON.stringify({ error: 'No pending invite found' }), {
      status: 404,
      headers: corsHeaders(),
    })
  }

  const { error } = await supabase
    .from('org_members')
    .update({
      status: 'active',
      user_id: user.id,
      joined_at: new Date().toISOString(),
    })
    .eq('id', invite.id)

  if (error) {
    return new Response(JSON.stringify({ error: 'Failed to accept invite' }), {
      status: 500,
      headers: corsHeaders(),
    })
  }

  return new Response(JSON.stringify({ ok: true }), {
    headers: { ...corsHeaders(), 'Content-Type': 'application/json' },
  })
})
