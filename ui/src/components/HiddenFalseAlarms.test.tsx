import { afterEach, describe, expect, it, vi } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { FindingsList } from './FindingsList'
import { Dashboard } from './Dashboard'
import { FindingDetail } from './FindingDetail'
import type { Finding, ScanResult } from '@/types'

const base: Omit<Finding, 'ID' | 'Title'> = {
  Scanner: 'bearer',
  Category: 'sast',
  Severity: 'critical',
  RawMessage: 'Hard-coded secrets are a risk.',
  FilePath: 'src/LoginForm.tsx',
  LineNumber: 6,
  CodeSnippet: 'password: "Password",',
  RuleID: 'javascript_lang_hardcoded_secret',
  Status: 'open',
}

const label: Finding = {
  ...base, ID: 'lbl', Title: 'Usage of hard-coded secret',
  Verdict: 'likely_fp', VerdictReason: 'This is the text label for a password field, not a password.', VerdictConfidence: 0.92,
}
const realKey: Finding = {
  ...base, ID: 'key', Title: 'Live Stripe key in code', FilePath: 'src/config.ts', LineNumber: 7,
  Verdict: 'confirmed', VerdictReason: 'A live secret key is written in the code.',
}
const unchecked: Finding = { ...base, ID: 'sql', Title: 'SQL injection', Severity: 'high', FilePath: 'src/db.ts' }

afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals() })

describe('hidden false alarms in the findings list', () => {
  it('hides likely false alarms from the list and counts them', () => {
    render(<FindingsList findings={[label, realKey, unchecked]} onSelect={() => {}} />)
    expect(screen.queryByText('Usage of hard-coded secret')).toBeNull()
    expect(screen.getByText('Live Stripe key in code')).toBeInTheDocument()
    expect(screen.getByText('SQL injection')).toBeInTheDocument()
    expect(screen.getByText('2 results')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /trojan hid 1 false alarm\b/i })).toBeInTheDocument()
  })

  it('opens to show each hidden finding with the reason', () => {
    render(<FindingsList findings={[label, realKey]} onSelect={() => {}} />)
    fireEvent.click(screen.getByRole('button', { name: /trojan hid 1 false alarm/i }))
    const rows = screen.getAllByTestId('hidden-false-alarm')
    expect(rows).toHaveLength(1)
    expect(rows[0]).toHaveTextContent('Usage of hard-coded secret')
    expect(rows[0]).toHaveTextContent('not a password')
  })

  it('"This is a real issue" saves the decision and reloads', async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true })
    vi.stubGlobal('fetch', fetchMock)
    const onChanged = vi.fn()
    render(<FindingsList findings={[label]} onSelect={() => {}} onChanged={onChanged} />)
    fireEvent.click(screen.getByRole('button', { name: /trojan hid 1 false alarm/i }))
    fireEvent.click(screen.getByRole('button', { name: /this is a real issue/i }))
    await waitFor(() => expect(onChanged).toHaveBeenCalled())
    expect(fetchMock).toHaveBeenCalledWith('/api/findings/lbl/real', { method: 'POST' })
  })

  it('shows no disclosure when nothing is hidden, and shows the triage note', () => {
    render(<FindingsList findings={[realKey]} onSelect={() => {}} triageNote="Trojan couldn't double-check every finding for false alarms." />)
    expect(screen.queryByText(/trojan hid/i)).toBeNull()
    expect(screen.getByTestId('triage-note')).toHaveTextContent('double-check')
  })
})

describe('finding detail verdict', () => {
  it('shows the AI reason and lets the user flag a shown finding as a false alarm', async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true })
    vi.stubGlobal('fetch', fetchMock)
    const onAction = vi.fn()
    render(<FindingDetail finding={realKey} onBack={() => {}} onAction={onAction} />)
    expect(screen.getByTestId('verdict')).toHaveTextContent('A live secret key is written in the code.')
    fireEvent.click(screen.getByRole('button', { name: /this is a false alarm/i }))
    await waitFor(() => expect(onAction).toHaveBeenCalled())
    expect(fetchMock).toHaveBeenCalledWith('/api/findings/key/false-alarm', { method: 'POST' })
  })

  it('offers "This is a real issue" on a hidden one', () => {
    render(<FindingDetail finding={label} onBack={() => {}} onAction={() => {}} />)
    expect(screen.getByRole('button', { name: /this is a real issue/i })).toBeInTheDocument()
  })
})

describe('hidden false alarms on the dashboard', () => {
  it('leaves them out of the issue count and says how many were hidden', () => {
    const scan: ScanResult = { timestamp: new Date().toISOString(), project_path: '/p', findings: [label, realKey, unchecked], locked_count: 0 }
    render(<Dashboard scan={scan} onViewFindings={() => {}} onSelectFinding={() => {}} />)
    expect(screen.getByRole('heading', { name: '2 issues found.' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /trojan hid 1 false alarm/i })).toBeInTheDocument()
    expect(screen.queryByText('Usage of hard-coded secret')).toBeNull()
  })
})
