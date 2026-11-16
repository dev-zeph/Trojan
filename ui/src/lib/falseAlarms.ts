import type { Finding } from '@/types'

// A finding Trojan's AI check (or the user, earlier) judged a likely false
// alarm. Hidden from the findings list and the counts, but listed under
// "Trojan hid N false alarms" with the reason, so nothing disappears silently.
export function isHiddenFalseAlarm(f: Finding): boolean {
  return f.Verdict === 'likely_fp'
}

// Open findings the user should see.
export function shownOpenFindings(findings: Finding[]): Finding[] {
  return findings.filter(f => f.Status === 'open' && !isHiddenFalseAlarm(f))
}

// Open findings hidden as likely false alarms.
export function hiddenFalseAlarms(findings: Finding[]): Finding[] {
  return findings.filter(f => f.Status === 'open' && isHiddenFalseAlarm(f))
}

export function falseAlarmLabel(n: number): string {
  return `Trojan hid ${n} false alarm${n === 1 ? '' : 's'}`
}
