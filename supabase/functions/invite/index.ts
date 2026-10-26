import { supabase } from '../_shared/supabase.ts'
import { validateToken, corsHeaders } from '../_shared/auth.ts'

const SITE_URL = 'https://trojancli.com'

async function sendInviteEmail(
  toEmail: string,
  inviterEmail: string,
  orgName: string,
): Promise<void> {
  const apiKey = Deno.env.get('RESEND_API_KEY')
  if (!apiKey) {
    console.warn('RESEND_API_KEY not set — skipping invite email')
    return
  }

  const acceptUrl = `${SITE_URL}/accept-invite`

  const html = `
    <div style="font-family:system-ui,sans-serif;max-width:480px;margin:0 auto;padding:32px 24px;color:#111">
      <h2 style="font-size:20px;font-weight:700;margin:0 0 8px">You're invited to join ${orgName} on Trojan</h2>
      <p style="color:#555;margin:0 0 24px;font-size:15px;line-height:1.5">
        ${inviterEmail} has invited you to their Trojan security team.<br>
        Trojan scans your code for vulnerabilities — your whole team, one subscription.
      </p>
      <a href="${acceptUrl}"
         style="display:inline-block;background:#111;color:#fff;text-decoration:none;padding:12px 24px;font-size:14px;font-weight:600;border-radius:6px">
        Accept invite →
      </a>
      <p style="color:#888;margin:24px 0 0;font-size:12px;line-height:1.5">
        Sign in (or create an account) with this email address to accept.<br>
        If you weren't expecting this, you can ignore it.
      </p>
      <hr style="border:none;border-top:1px solid #eee;margin:24px 0">
      <p style="color:#aaa;font-size:11px;margin:0">
        Trojan · <a href="${SITE_URL}" style="color:#aaa">trojancli.com</a>
      </p>
    </div>
  `

  await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      from: 'Trojan <hi@trojancli.com>',
      to: [toEmail],
      subject: `${inviterEmail} invited you to their Trojan team`,
      html,
    }),
  })
}

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
    .select('id, name, seat_limit')
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
    return new Response(JSON.stringify({ error: 'Failed to create invite' }), {
      status: 500,
      headers: corsHeaders(),
    })
  }

  // Send invite email (non-blocking — don't fail the invite if email fails)
  await sendInviteEmail(email.toLowerCase(), user.email, org.name)

  return new Response(JSON.stringify({ ok: true }), {
    headers: { ...corsHeaders(), 'Content-Type': 'application/json' },
  })
})
