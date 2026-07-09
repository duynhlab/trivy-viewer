import { useState, useEffect, useCallback, useMemo } from 'react'
import { useSearchParams, useNavigate, useOutletContext } from 'react-router-dom'
import ReportsView from '../components/ReportsView'
import { getReports, getRegisteredClusters } from '../api'
import type { ReportMeta, ReportType, Filters, Stats, ClusterInfo } from '../types'

interface LayoutContext {
  stats: Stats | null
  clusterOptions: ClusterInfo[]
  namespaceOptions: string[]
  setFilterCluster: (cluster: string) => void
}

interface ReportsPageProps {
  reportType: ReportType
}

export default function ReportsPage({ reportType }: ReportsPageProps) {
  const { stats, clusterOptions, namespaceOptions, setFilterCluster } = useOutletContext<LayoutContext>()
  const [searchParams, setSearchParams] = useSearchParams()
  const navigate = useNavigate()
  const [reports, setReports] = useState<ReportMeta[]>([])
  const [registeredCount, setRegisteredCount] = useState<number | null>(null)

  const filters: Filters = useMemo(() => ({
    cluster: searchParams.get('cluster') || '',
    namespace: searchParams.get('namespace') || '',
    app: searchParams.get('app') || '',
    component: searchParams.get('component') || '',
  }), [searchParams])

  // Sync cluster filter to Layout for namespace loading
  useEffect(() => {
    setFilterCluster(filters.cluster)
  }, [filters.cluster, setFilterCluster])

  // Load reports when filters or report type change
  const loadReports = useCallback(() => {
    getReports(reportType, filters)
      .then((data) => setReports(data.items || []))
      .catch(() => setReports([]))
  }, [reportType, filters])

  useEffect(() => {
    loadReports()
  }, [loadReports])

  useEffect(() => {
    getRegisteredClusters()
      .then((items) => setRegisteredCount(Array.isArray(items) ? items.length : 0))
      .catch(() => setRegisteredCount(null))
  }, [])

  const hasActiveFilters = !!(filters.cluster || filters.namespace || filters.app)

  const handleFilterChange = useCallback((key: string, value: string) => {
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev)
      next.set(key, value)
      if (key === 'cluster') next.delete('namespace')
      // Remove empty params
      if (!value) next.delete(key)
      return next
    })
  }, [setSearchParams])

  const handleFilterClear = useCallback((key: string) => {
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev)
      next.delete(key)
      if (key === 'cluster') next.delete('namespace')
      return next
    })
  }, [setSearchParams])

  const handleSelectReport = useCallback((report: ReportMeta) => {
    const basePath = reportType === 'vulnerabilityreport' ? '/vulnerabilities' : '/sbom'
    navigate(`${basePath}/${encodeURIComponent(report.cluster)}/${encodeURIComponent(report.namespace)}/${encodeURIComponent(report.name)}`)
    window.scrollTo(0, 0)
  }, [reportType, navigate])

  const memoizedReports = useMemo(() => reports, [reports])

  return (
    <ReportsView
      reports={memoizedReports}
      reportType={reportType}
      filters={filters}
      stats={stats}
      clusterOptions={clusterOptions}
      namespaceOptions={namespaceOptions}
      onFilterChange={handleFilterChange}
      onFilterClear={handleFilterClear}
      onSelectReport={handleSelectReport}
      registeredCount={registeredCount}
      hasActiveFilters={hasActiveFilters}
      onClearAllFilters={() => setSearchParams({})}
    />
  )
}
