import type { ReactNode } from 'react'
import { openExternal } from '@/lib/openExternal'

interface Props {
  href: string
  className?: string
  children: ReactNode
}

// Looks like a link, but never navigates the report iframe itself -- clicking
// it asks the desktop shell to open `href` in the user's real browser. See
// lib/openExternal for why a plain <a> (even with target="_blank") is wrong here.
export function ExternalLink({ href, className, children }: Props) {
  return (
    <button type="button" onClick={() => openExternal(href)} className={className}>
      {children}
    </button>
  )
}
