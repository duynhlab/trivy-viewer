import { useState, useCallback, useRef, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import FilterPopup from './FilterPopup'
import ScrollNav from './ScrollNav'
import EmptyState from './EmptyState'
import { escapeHtml, formatDate, escapeCsvField, formatDateForFilename, randomHash, downloadCsv } from '../utils'
import type { ReportMeta, ReportType, Filters, Stats, ClusterInfo, VulnSummary } from '../types'
import styles from './ReportsView.module.css'

interface ReportsViewProps {
  reports: ReportMeta[]
  reportType: ReportType
  filters: Filters
  stats: Stats | null
  clusterOptions: ClusterInfo[]
  namespaceOptions: string[]
  onFilterChange: (key: string, value: string) => void
  onFilterClear: (key: string) => void
  onSelectReport: (report: ReportMeta) => void
  registeredCount?: number | null
  hasActiveFilters?: boolean
  onClearAllFilters?: () => void
}

type SortKey = string | null

export default function ReportsView({
  reports,
  reportType,
  filters,
  stats,
  clusterOptions,
  namespaceOptions,
  onFilterChange,
  onFilterClear,
  onSelectReport,
  registeredCount = null,
  hasActiveFilters = false,
  onClearAllFilters,
}: ReportsViewProps) {
  const navigate = useNavigate()
  const [sortColumn, setSortColumn] = useState<SortKey>(null)
  const [sortDirection, setSortDirection] = useState<'asc' | 'desc'>('asc')
  const [filterPopup, setFilterPopup] = useState<{ key: 'cluster' | 'namespace' | 'app'; anchorRect: DOMRect } | null>(null)
  const containerRef = useRef<HTMLDivElement>(null)

  // Reset sort on report type change
  useEffect(() => {
    setSortColumn(null)
    setSortDirection('asc')
  }, [reportType])

  const isFilterActive = filters.cluster || filters.namespace || filters.app

  const filteredSeverity: VulnSummary = reports.reduce(
    (acc, r) => {
      if (reportType === 'vulnerabilityreport' && r.summary) {
        acc.critical += r.summary.critical || 0
        acc.high += r.summary.high || 0
        acc.medium += r.summary.medium || 0
        acc.low += r.summary.low || 0
        acc.unknown += r.summary.unknown || 0
      }
      return acc
    },
    { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 },
  )

  const handleSort = useCallback((key: string) => {
    setSortColumn((prev) => {
      if (prev === key) {
        setSortDirection((d) => (d === 'asc' ? 'desc' : 'asc'))
        return key
      }
      setSortDirection('asc')
      return key
    })
  }, [])

  const sortedReports = [...reports].sort((a, b) => {
    if (!sortColumn) return 0
    const dir = sortDirection === 'desc' ? -1 : 1
    if (sortColumn === 'cluster') return dir * (a.cluster || '').localeCompare(b.cluster || '')
    if (sortColumn === 'namespace') return dir * (a.namespace || '').localeCompare(b.namespace || '')
    if (sortColumn === 'components') return dir * ((a.components_count || 0) - (b.components_count || 0))
    if (sortColumn === 'updated_at') {
      const aTime = a.updated_at ? new Date(a.updated_at).getTime() : 0
      const bTime = b.updated_at ? new Date(b.updated_at).getTime() : 0
      return dir * (aTime - bTime)
    }
    // Severity columns
    const aVal = (a.summary?.[sortColumn as keyof VulnSummary] as number) || 0
    const bVal = (b.summary?.[sortColumn as keyof VulnSummary] as number) || 0
    return dir * (aVal - bVal)
  })

  const openFilter = (key: 'cluster' | 'namespace' | 'app', e: React.MouseEvent) => {
    e.stopPropagation()
    const rect = (e.currentTarget as HTMLElement).getBoundingClientRect()
    setFilterPopup({ key, anchorRect: rect })
  }

  const handleFilterApply = (key: string, value: string) => {
    onFilterChange(key, value)
    setFilterPopup(null)
  }

  const handleFilterClear = (key: string) => {
    onFilterClear(key)
    setFilterPopup(null)
  }

  const exportToCsv = () => {
    if (reports.length === 0) return
    let csv = ''
    let filename = ''
    if (reportType === 'vulnerabilityreport') {
      csv = 'Cluster,Namespace,Application,Image,Critical,High,Medium,Low,Unknown,Updated\n'
      reports.forEach((r) => {
        const s = r.summary || { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 }
        csv += [escapeCsvField(r.cluster), escapeCsvField(r.namespace), escapeCsvField(r.app), escapeCsvField(r.image), s.critical, s.high, s.medium, s.low, s.unknown, r.updated_at || ''].join(',') + '\n'
      })
      filename = `trivy-viewer-vuln-${formatDateForFilename()}-${randomHash()}.csv`
    } else {
      csv = 'Cluster,Namespace,Application,Image,Components,Updated\n'
      reports.forEach((r) => {
        csv += [escapeCsvField(r.cluster), escapeCsvField(r.namespace), escapeCsvField(r.app), escapeCsvField(r.image), r.components_count || 0, r.updated_at || ''].join(',') + '\n'
      })
      filename = `trivy-viewer-sbom-${formatDateForFilename()}-${randomHash()}.csv`
    }
    downloadCsv(csv, filename)
  }

  const totalCount = stats ? (reportType === 'vulnerabilityreport' ? stats.total_vuln_reports : stats.total_sbom_reports) : 0
  const reportTypeName = reportType === 'vulnerabilityreport' ? 'Vulnerability' : 'SBOM'

  const renderSeverityCount = (level: keyof VulnSummary) => {
    const filtered = filteredSeverity[level]
    const total = stats ? (stats[`total_${level}` as keyof Stats] as number) || 0 : 0
    if (isFilterActive && total > 0) {
      return <><span className={styles.filteredCount}>{filtered}</span><span className={styles.totalCount}> / {total}</span></>
    }
    return <>{total}</>
  }

  const sortIcon = (key: string) => {
    if (sortColumn === key) {
      return <i className={`fa-solid ${sortDirection === 'desc' ? 'fa-sort-down' : 'fa-sort-up'} ${styles.sortIcon}`} style={{ color: 'var(--accent)' }} />
    }
    return <i className={`fa-solid fa-sort ${styles.sortIcon}`} />
  }

  const filterBtn = (key: 'cluster' | 'namespace' | 'app') => (
    <button
      className={filters[key] ? styles.filterBtnActive : styles.filterBtn}
      title="Filter"
      onClick={(e) => openFilter(key, e)}
    >
      <i className="fa-solid fa-filter" />
    </button>
  )

  const renderEmptyBody = () => {
    if (hasActiveFilters) {
      return (
        <EmptyState
          icon="fa-filter"
          title="No reports match your filters"
          description="Try clearing filters or choosing a different cluster or namespace."
          action={onClearAllFilters ? { label: 'Clear filters', onClick: onClearAllFilters } : undefined}
        />
      )
    }
    if (registeredCount === 0) {
      return (
        <EmptyState
          icon="fa-server"
          title={`No ${reportTypeName.toLowerCase()} reports yet`}
          description="Register edge clusters on the Hub so the scraper can pull Trivy Operator reports. After registration, wait up to a minute for the first sync."
          action={{ label: 'Register clusters', to: '/admin/clusters' }}
          secondaryAction={{ label: 'View dashboard', to: '/dashboard' }}
        />
      )
    }
    if (registeredCount !== null && registeredCount > 0) {
      return (
        <EmptyState
          icon="fa-hourglass-half"
          title="Waiting for scraper sync"
          description="Clusters are registered but no reports have arrived yet. Ensure Trivy Operator CRDs exist on edge clusters and sample reports or scans are present."
          action={{ label: 'Cluster status', to: '/admin/clusters' }}
          secondaryAction={{ label: 'System status', to: '/version' }}
        />
      )
    }
    return (
      <EmptyState
        icon="fa-inbox"
        title="No reports found"
        description="Reports will appear here once the scraper ingests Trivy Operator custom resources."
        action={{ label: 'Register clusters', to: '/admin/clusters' }}
      />
    )
  }

  return (
    <section ref={containerRef} className={styles.container}>
      <div className={styles.toolbar}>
        <div className={styles.toolbarLeft}>
          <span className={styles.statItem}>
            <span className={styles.statLabel}>Clusters</span>
            <span className={styles.statValue}>{stats?.total_clusters || 0}</span>
          </span>
          <span className={styles.statItem}>
            <span className={styles.statLabel}>{reportTypeName}</span>
            <span className={styles.statValue}>
              {isFilterActive && totalCount > 0 ? (
                <><span className={styles.filteredCount}>{reports.length}</span><span className={styles.totalCount}> / {totalCount}</span></>
              ) : (
                reports.length
              )}
            </span>
          </span>
          {reportType === 'vulnerabilityreport' && (
            <div className={styles.severityTotals}>
              {(['critical', 'high', 'medium', 'low', 'unknown'] as const).map((level) => (
                <span key={level} className={`${styles.severityTotal} ${styles[level]}`}>
                  <span className={styles.severityLabel}>{level.charAt(0).toUpperCase() + level.slice(1)}</span>
                  <span className={styles.severityCount}>{renderSeverityCount(level)}</span>
                </span>
              ))}
            </div>
          )}
        </div>
        <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
          {reportType === 'vulnerabilityreport' && (
            <button
              className="btn-export"
              onClick={() => navigate('/vulnerabilities/search')}
              title="Search CVEs across all vulnerability reports"
            >
              <i className="fa-solid fa-magnifying-glass" /> Vulnerability Search
            </button>
          )}
          {reportType === 'sbomreport' && (
            <button
              className="btn-export"
              onClick={() => navigate('/sbom/components')}
              title="Search components across all SBOM reports"
            >
              <i className="fa-solid fa-magnifying-glass" /> Component Search
            </button>
          )}
          <button className="btn-export" onClick={exportToCsv} disabled={reports.length === 0} title="Export to CSV">
            <i className="fa-solid fa-arrow-down" /> Export CSV
          </button>
        </div>
      </div>

      <table className={styles.table}>
        <thead>
          <tr>
            <th className="sortable" onClick={() => handleSort('cluster')}>
              <span className={styles.thContent}>Cluster</span>
              {sortIcon('cluster')}
              {filterBtn('cluster')}
            </th>
            <th className="sortable" onClick={() => handleSort('namespace')}>
              <span className={styles.thContent}>Namespace</span>
              {sortIcon('namespace')}
              {filterBtn('namespace')}
            </th>
            <th>
              <span className={styles.thContent}>Application</span>
              {filterBtn('app')}
            </th>
            <th>Image</th>
            {reportType === 'vulnerabilityreport' ? (
              <>
                <th className={`${styles.severityCol} sortable`} onClick={() => handleSort('critical')}>C {sortIcon('critical')}</th>
                <th className={`${styles.severityCol} sortable`} onClick={() => handleSort('high')}>H {sortIcon('high')}</th>
                <th className={`${styles.severityCol} sortable`} onClick={() => handleSort('medium')}>M {sortIcon('medium')}</th>
                <th className={`${styles.severityCol} sortable`} onClick={() => handleSort('low')}>L {sortIcon('low')}</th>
                <th className={`${styles.severityCol} sortable`} onClick={() => handleSort('unknown')}>U {sortIcon('unknown')}</th>
              </>
            ) : (
              <th className="sortable" onClick={() => handleSort('components')}>Components {sortIcon('components')}</th>
            )}
            <th className="sortable" onClick={() => handleSort('updated_at')}>Updated {sortIcon('updated_at')}</th>
          </tr>
        </thead>
        <tbody>
          {sortedReports.length === 0 ? (
            <tr>
              <td colSpan={reportType === 'vulnerabilityreport' ? 10 : 6} className={styles.emptyCell}>
                {renderEmptyBody()}
              </td>
            </tr>
          ) : (
            sortedReports.map((report) => (
              <tr key={`${report.cluster}/${report.namespace}/${report.name}`} onClick={() => onSelectReport(report)}>
                <td>{escapeHtml(report.cluster)}</td>
                <td>{escapeHtml(report.namespace)}</td>
                <td>{escapeHtml(report.app || '-')}</td>
                <td className={styles.imageCell}>
                  {escapeHtml(report.image || '-')}
                  {report.notes?.trim() && <i className={`fa-solid fa-note-sticky ${styles.notesIndicator}`} title="Has notes" />}
                </td>
                {reportType === 'vulnerabilityreport' ? (
                  <>
                    {(['critical', 'high', 'medium', 'low', 'unknown'] as const).map((level) => {
                      const count = report.summary?.[level] || 0
                      return (
                        <td key={level} className={styles.severityCol}>
                          {count === 0 ? (
                            <span className="severity-zero">0</span>
                          ) : (
                            <span className={`severity-badge severity-${level}`}>{count}</span>
                          )}
                        </td>
                      )
                    })}
                  </>
                ) : (
                  <td><span className="components-badge">{report.components_count || 0}</span></td>
                )}
                <td>{formatDate(report.updated_at)}</td>
              </tr>
            ))
          )}
        </tbody>
      </table>

      {filterPopup && containerRef.current && (
        <FilterPopup
          filterKey={filterPopup.key}
          currentValue={filters[filterPopup.key]}
          clusterOptions={clusterOptions}
          namespaceOptions={namespaceOptions}
          anchorRect={filterPopup.anchorRect}
          containerRect={containerRef.current.getBoundingClientRect()}
          onApply={handleFilterApply}
          onClear={handleFilterClear}
          onClose={() => setFilterPopup(null)}
        />
      )}

      <ScrollNav />
    </section>
  )
}
