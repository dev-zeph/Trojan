import { describe, expect, it, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { FindingDetail } from './FindingDetail'
import type { Finding } from '@/types'

// Regression guard for "Upgrade Plan traps the user": the token top-up CTA
// used to be a plain <a href="https://trojancli.com/pricing">, which
// navigates the report IFRAME itself when this page is embedded in the
// desktop shell, stranding the user on trojancli.com with no way back.
vi.mock('@/lib/openExternal', () => ({ openExternal: vi.fn() }))

import { openExternal } from '@/lib/openExternal'

const finding: Finding = {
  ID: 'f1',
  Scanner: 'semgrep',
  Category: 'injection',
  Severity: 'high',
  Title: 'SQL injection',
  RawMessage: 'User input reaches a query unsanitized.',
  FilePath: 'src/db.ts',
  LineNumber: 42,
  CodeSnippet: 'db.query(userInput)',
  RuleID: 'sql-injection',
  Status: 'open',
  // No Simply/Actions -- exercises the "Get Trojan Tokens" CTA branch.
}

describe('FindingDetail token-gated CTAs', () => {
  it('renders the pricing CTA as a button, not a navigating anchor', () => {
    render(<FindingDetail finding={finding} onBack={() => {}} onAction={() => {}} />)

    // The old <a href="https://trojancli.com/pricing"> is exactly the bug:
    // clicking it would navigate the iframe. There must be no such anchor.
    const pricingAnchors = screen.queryAllByRole('link', { name: /tokens/i })
    expect(pricingAnchors).toHaveLength(0)
  })

  it('clicking "Get Trojan Tokens" calls the opener instead of navigating', () => {
    render(<FindingDetail finding={finding} onBack={() => {}} onAction={() => {}} />)

    const buttons = screen.getAllByRole('button', { name: /get trojan tokens/i })
    expect(buttons.length).toBeGreaterThan(0)
    fireEvent.click(buttons[0])

    expect(openExternal).toHaveBeenCalledWith('https://trojancli.com/pricing')
  })

  it('does not say "Upgrade to Pro" (stale post-token-migration copy)', () => {
    render(<FindingDetail finding={finding} onBack={() => {}} onAction={() => {}} />)
    expect(screen.queryByText(/upgrade to pro/i)).toBeNull()
  })
})
