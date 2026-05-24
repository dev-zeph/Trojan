import { useEffect, useState } from 'react'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Dashboard } from './components/Dashboard'
import { FindingsList } from './components/FindingsList'
import { FindingDetail } from './components/FindingDetail'
import { getLatestScan } from './api'
import type { Finding, ScanResult } from './types'

export default function App() {
  const [scan, setScan] = useState<ScanResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [selected, setSelected] = useState<Finding | null>(null)

  async function loadScan() {
    try {
      const data = await getLatestScan()
      setScan(data)
    } catch {
      setError('Could not load scan results. Make sure the Trojan server is running.')
    }
  }

  useEffect(() => { loadScan() }, [])

  if (error) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <p className="text-muted-foreground text-sm">{error}</p>
      </div>
    )
  }

  if (!scan) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <p className="text-muted-foreground text-sm">Loading scan results...</p>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-background">
      <header className="border-b px-6 py-4 flex items-center gap-3">
        <span className="font-bold text-lg tracking-tight">Trojan</span>
        <span className="text-muted-foreground text-sm">Security Report</span>
      </header>

      <main className="max-w-5xl mx-auto px-6 py-8">
        {selected ? (
          <FindingDetail
            finding={selected}
            onBack={() => setSelected(null)}
            onAction={() => { setSelected(null); loadScan() }}
          />
        ) : (
          <Tabs defaultValue="dashboard">
            <TabsList className="mb-6">
              <TabsTrigger value="dashboard">Dashboard</TabsTrigger>
              <TabsTrigger value="findings">
                Findings ({scan.findings.length})
              </TabsTrigger>
            </TabsList>

            <TabsContent value="dashboard">
              <Dashboard scan={scan} />
            </TabsContent>

            <TabsContent value="findings">
              <FindingsList
                findings={scan.findings}
                onSelect={setSelected}
              />
            </TabsContent>
          </Tabs>
        )}
      </main>
    </div>
  )
}
