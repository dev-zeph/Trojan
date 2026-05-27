import type { Severity } from '@/types'

const dot: Record<Severity, string> = {
  critical: 'bg-red-500',
  high: 'bg-orange-400',
  medium: 'bg-yellow-400',
  low: 'bg-blue-400',
  info: 'bg-gray-400',
}

const label: Record<Severity, string> = {
  critical: 'text-red-500',
  high: 'text-orange-400',
  medium: 'text-yellow-500 dark:text-yellow-400',
  low: 'text-blue-400',
  info: 'text-gray-400',
}

export function SeverityDot({ severity }: { severity: Severity }) {
  return (
    <span className={`inline-block w-1.5 h-1.5 rounded-full shrink-0 mt-1.5 ${dot[severity]}`} />
  )
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={`text-xs font-medium uppercase tracking-widest ${label[severity]}`}>
      {severity}
    </span>
  )
}
