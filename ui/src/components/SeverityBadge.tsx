import { Badge } from '@/components/ui/badge'
import type { Severity } from '@/types'

const styles: Record<Severity, string> = {
  critical: 'bg-red-600 text-white hover:bg-red-600',
  high: 'bg-orange-500 text-white hover:bg-orange-500',
  medium: 'bg-yellow-500 text-white hover:bg-yellow-500',
  low: 'bg-blue-500 text-white hover:bg-blue-500',
  info: 'bg-gray-400 text-white hover:bg-gray-400',
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <Badge className={styles[severity]}>
      {severity}
    </Badge>
  )
}
