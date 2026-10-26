import { supabase } from '../_shared/supabase.ts'
import { validateToken, corsHeaders } from '../_shared/auth.ts'
import { parseBody } from '../_shared/body.ts'

// In-app feedback from the desktop app.
//
// Stored in user_feedback AND emailed, on purpose: the table is what makes a
// tester round analysable (count the categories, group the complaints), the
// email is what makes it actually get read the same day.
//
// The store is the source of truth. If Resend is down or unconfigured the row
// still lands and the caller still gets a 200 -- losing the notification is an
// inconvenience, telling a tester their report failed when we have it is a lie
// that costs us the next report too.

const NOTIFY_TO = 'hi@trojancli.com'

const CATEGORIES = ['bug', 'idea', 'confusing', 'other'] as const
type Category = typeof CATEGORIES[number]

/** Matches the CHECK constraint in migration 021. Keep the two in step. */
const MAX_MESSAGE = 4000

interface FeedbackBody {
  category?: string
  message?: string
  appVersion?: string
  view?: string
}

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response(null, { headers: corsHeaders() })
  if (req.method !== 'POST') return json({ error: 'Method not allowed' }, 405)

  const token = req.headers.get('authorization')?.replace('Bearer ', '') ?? ''
  const user = await validateToken(token)
  if (!user) return json({ error: 'Unauthorized' }, 401)

  // parseBody unwraps the base64 { encoded } envelope. Not optional here: bug
  // reports routinely quote the very payloads Trojan finds ("<script>",
  // "' OR 1=1"), and Cloudflare's WAF 403s those in a raw body -- which the
  // browser then surfaces as an unexplained CORS error.
  let body: FeedbackBody
  try {
    body = await parseBody<FeedbackBody>(req)
  } catch {
    return json({ error: 'Malformed request body' }, 400)
  }

  const message = (body.message ?? '').trim()
  if (!message) return json({ error: 'Feedback cannot be empty.' }, 400)
  if (message.length > MAX_MESSAGE) {
    return json({ error: `Feedback is limited to ${MAX_MESSAGE} characters.` }, 400)
  }

  // Anything unrecognised becomes 'other' rather than a 400. The category is
  // ours, not the tester's, and rejecting a written-out report over a bad enum
  // would throw away the only part that matters.
  const category: Category = (CATEGORIES as readonly string[]).includes(body.category ?? '')
    ? body.category as Category
    : 'other'

  const { data: row, error } = await supabase
    .from('user_feedback')
    .insert({
      user_id: user.id,
      email: user.email,
      category,
      message,
      app_version: trunc(body.appVersion, 40),
      view: trunc(body.view, 40),
    })
    .select('id')
    .single()

  if (error) {
    console.error('feedback: insert failed', { userId: user.id, error: error.message })
    return json({ error: 'Could not save your feedback. Please try again.' }, 500)
  }

  await notify({ email: user.email, category, message, appVersion: body.appVersion, view: body.view })

  return json({ ok: true, id: row.id })
})

/** Trim optional client-supplied context to something sane before storing. */
function trunc(v: string | undefined, max: number): string | null {
  const s = (v ?? '').trim()
  return s ? s.slice(0, max) : null
}

/**
 * Email the maintainer. Never throws: the feedback is already durably stored,
 * so a notification failure must not turn a saved report into an error page.
 */
async function notify(f: {
  email: string; category: Category; message: string
  appVersion?: string; view?: string
}): Promise<void> {
  const apiKey = Deno.env.get('RESEND_API_KEY')
  if (!apiKey) {
    console.warn('feedback: RESEND_API_KEY not set, skipping notification email')
    return
  }

  const context = [
    `From: ${f.email}`,
    `Category: ${f.category}`,
    `App: ${f.appVersion ?? 'unknown'}`,
    `Screen: ${f.view ?? 'unknown'}`,
  ].join('<br>')

  // escapeHtml because the message is untrusted text going into an HTML email.
  const html = `
    <div style="font-family:system-ui,sans-serif;max-width:560px;margin:0 auto;padding:32px 24px;color:#111">
      <p style="font-size:12px;letter-spacing:.08em;text-transform:uppercase;color:#666;margin:0 0 16px">
        Trojan feedback
      </p>
      <div style="white-space:pre-wrap;font-size:15px;line-height:1.5;padding:16px;background:#f7f6f4;border:1px solid #d3d0ca">${escapeHtml(f.message)}</div>
      <p style="font-size:13px;color:#56565e;margin:16px 0 0">${context}</p>
    </div>`

  try {
    const res = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        from: 'Trojan <hi@trojancli.com>',
        to: [NOTIFY_TO],
        reply_to: f.email,
        subject: `[${f.category}] feedback from ${f.email}`,
        html,
      }),
    })
    if (!res.ok) {
      console.error('feedback: resend rejected the email', { status: res.status })
    }
  } catch (e) {
    console.error('feedback: notification email failed', { error: String(e) })
  }
}

function escapeHtml(s: string): string {
  return s
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
}

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...corsHeaders(), 'Content-Type': 'application/json' },
  })
}
