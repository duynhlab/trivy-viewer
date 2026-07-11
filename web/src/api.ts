import type {
  ApiLogEntry,
  ApiLogStats,
  ClusterInfo,
  ComponentSearchResult,
  ConfigResponse,
  VulnSearchResult,
  CreateTokenResponse,
  Filters,
  FullReport,
  ListResponse,
  ReportMeta,
  ReportType,
  Stats,
  StatusResponse,
  TokenInfo,
  TrendResponse,
  VersionResponse,
  WatcherStatusResponse,
} from './types'

/**
 * Redirect to the login page and return a never-resolving promise so the
 * caller's chain stops (the page is about to navigate away anyway).
 */
function redirectToLogin<T>(): Promise<T> {
  const returnTo = encodeURIComponent(window.location.pathname)
  window.location.href = `/auth/login?return_to=${returnTo}`
  return new Promise(() => {})
}

/** Build an Error from a failed response: `body.error`, else the fallback. */
async function errorFrom(response: Response, fallback?: string): Promise<Error> {
  const body = (await response.json().catch(() => ({}))) as { error?: string }
  return new Error(body.error || fallback || `HTTP ${response.status}`)
}

interface RequestOptions {
  method?: string
  body?: unknown
  /** Fallback error message when the response has no `error` field. */
  errorMessage?: string
}

/**
 * Shared request helper: 401 redirects to login, any other non-OK status
 * throws with the server's `error` message, OK parses JSON.
 */
async function request<T>(endpoint: string, opts: RequestOptions = {}): Promise<T> {
  const init: RequestInit = { method: opts.method ?? 'GET' }
  if (opts.body !== undefined) {
    init.headers = { 'Content-Type': 'application/json' }
    init.body = JSON.stringify(opts.body)
  }
  const response = await fetch(endpoint, init)
  if (response.status === 401) {
    return redirectToLogin<T>()
  }
  if (!response.ok) {
    throw await errorFrom(response, opts.errorMessage)
  }
  return response.json() as Promise<T>
}

export function getReports(
  reportType: ReportType,
  filters: Filters,
): Promise<ListResponse<ReportMeta>> {
  const params = new URLSearchParams()
  if (filters.cluster) params.append('cluster', filters.cluster)
  if (filters.namespace) params.append('namespace', filters.namespace)
  if (filters.app) params.append('app', filters.app)
  if (filters.component) params.append('component', filters.component)

  const endpoint =
    reportType === 'vulnerabilityreport'
      ? `/api/v1/vulnerabilityreports?${params}`
      : `/api/v1/sbomreports?${params}`

  return request(endpoint)
}

export function getReportDetail(
  reportType: ReportType,
  cluster: string,
  namespace: string,
  name: string,
): Promise<FullReport> {
  const base =
    reportType === 'vulnerabilityreport'
      ? '/api/v1/vulnerabilityreports'
      : '/api/v1/sbomreports'
  return request(
    `${base}/${encodeURIComponent(cluster)}/${encodeURIComponent(namespace)}/${encodeURIComponent(name)}`,
  )
}

export function getStats(): Promise<Stats> {
  return request('/api/v1/stats')
}

export function getClusters(): Promise<ListResponse<ClusterInfo>> {
  return request('/api/v1/clusters')
}

export function getNamespaces(
  cluster?: string,
): Promise<ListResponse<string>> {
  const endpoint = cluster
    ? `/api/v1/namespaces?cluster=${encodeURIComponent(cluster)}`
    : '/api/v1/namespaces'
  return request(endpoint)
}

export function getWatcherStatus(): Promise<WatcherStatusResponse> {
  return request('/api/v1/watcher/status')
}

export function getVersion(): Promise<VersionResponse> {
  return request('/api/v1/version')
}

export function getStatus(): Promise<StatusResponse> {
  return request('/api/v1/status')
}

export function getConfig(): Promise<ConfigResponse> {
  return request('/api/v1/config')
}

export function getDashboardTrends(
  range: string,
  cluster?: string,
): Promise<TrendResponse> {
  const params = new URLSearchParams({ range })
  if (cluster) params.append('cluster', cluster)
  return request(`/api/v1/dashboard/trends?${params}`)
}

export async function listTokens(): Promise<{ tokens: TokenInfo[] }> {
  return request('/api/v1/auth/tokens')
}

export async function createToken(
  name: string,
  description: string,
  expiresDays: number,
): Promise<CreateTokenResponse> {
  return request('/api/v1/auth/tokens', {
    method: 'POST',
    body: { name, description, expires_days: expiresDays },
    errorMessage: 'Failed to create token',
  })
}

export async function deleteToken(tokenId: number): Promise<boolean> {
  const response = await fetch(`/api/v1/auth/tokens/${tokenId}`, {
    method: 'DELETE',
  })
  if (response.status === 401) {
    return redirectToLogin<boolean>()
  }
  return response.ok
}

export function searchVulnerabilities(
  q: string,
  limit?: number,
  offset?: number,
): Promise<ListResponse<VulnSearchResult>> {
  const params = new URLSearchParams({ q })
  if (limit !== undefined) params.append('limit', String(limit))
  if (offset !== undefined) params.append('offset', String(offset))
  return request(`/api/v1/vulnerabilityreports/vulnerabilities/search?${params}`)
}

export function suggestVulnerabilities(
  q: string,
  limit?: number,
): Promise<string[]> {
  const params = new URLSearchParams({ q })
  if (limit !== undefined) params.append('limit', String(limit))
  return request(`/api/v1/vulnerabilityreports/vulnerabilities/suggest?${params}`)
}

export function suggestSbomComponents(
  q: string,
  limit?: number,
): Promise<string[]> {
  const params = new URLSearchParams({ q })
  if (limit !== undefined) params.append('limit', String(limit))
  return request(`/api/v1/sbomreports/components/suggest?${params}`)
}

export function searchSbomComponents(
  component: string,
  limit?: number,
  offset?: number,
): Promise<ListResponse<ComponentSearchResult>> {
  const params = new URLSearchParams({ component })
  if (limit !== undefined) params.append('limit', String(limit))
  if (offset !== undefined) params.append('offset', String(offset))
  return request(`/api/v1/sbomreports/components/search?${params}`)
}

// ───── Admin API ─────

export interface AdminLogsParams {
  method?: string
  path?: string
  status_min?: number
  status_max?: number
  user?: string
  limit?: number
  offset?: number
}

export function getApiLogs(
  params: AdminLogsParams = {},
): Promise<ListResponse<ApiLogEntry>> {
  const search = new URLSearchParams()
  if (params.method) search.append('method', params.method)
  if (params.path) search.append('path', params.path)
  if (params.status_min !== undefined)
    search.append('status_min', String(params.status_min))
  if (params.status_max !== undefined)
    search.append('status_max', String(params.status_max))
  if (params.user) search.append('user', params.user)
  if (params.limit !== undefined) search.append('limit', String(params.limit))
  if (params.offset !== undefined)
    search.append('offset', String(params.offset))
  return request(`/api/v1/admin/logs?${search}`)
}

export function getApiLogStats(): Promise<ApiLogStats> {
  return request('/api/v1/admin/logs/stats')
}

export async function cleanupApiLogs(
  retentionDays: number,
): Promise<{ deleted: number; retention_days: number }> {
  return request(`/api/v1/admin/logs?retention_days=${retentionDays}`, {
    method: 'DELETE',
    errorMessage: 'Access denied',
  })
}

// ── Alerts ──

import type { AlertMatchers, AlertPreviewResult, AlertRule, AlertRuleInput } from './types'

export interface AlertListResponse {
  items: AlertRule[]
  total: number
  configmap: string
  namespace: string
}

export async function listAlerts(): Promise<AlertListResponse> {
  return request('/api/v1/alerts')
}

export async function getAlert(name: string): Promise<AlertRule> {
  return request(`/api/v1/alerts/${encodeURIComponent(name)}`)
}

export async function createAlert(rule: AlertRuleInput): Promise<AlertRule> {
  return request('/api/v1/alerts', { method: 'POST', body: rule })
}

export async function updateAlert(name: string, rule: AlertRuleInput): Promise<AlertRule> {
  return request(`/api/v1/alerts/${encodeURIComponent(name)}`, {
    method: 'PUT',
    body: rule,
  })
}

export async function previewAlert(matchers: AlertMatchers): Promise<AlertPreviewResult> {
  return request('/api/v1/alerts/preview', { method: 'POST', body: { matchers } })
}

export async function testAlertDraft(
  rule: AlertRuleInput,
): Promise<import('./types').AlertTestResponse> {
  return request('/api/v1/alerts/test', { method: 'POST', body: rule })
}

export async function deleteAlert(name: string): Promise<void> {
  const res = await fetch(`/api/v1/alerts/${encodeURIComponent(name)}`, {
    method: 'DELETE',
  })
  if (res.status === 401) {
    return redirectToLogin<void>()
  }
  // 204 has no JSON body, so this cannot go through request().
  if (!res.ok && res.status !== 204) {
    throw await errorFrom(res)
  }
}

// ── Hub-pull cluster registration ──

export interface RegisteredCluster {
  name: string
  server: string
  namespaces: string[]
  insecure: boolean
  /** True for the auto-registered Hub-self entry. */
  in_cluster?: boolean
  /** Live probe result computed at list time (server calls /version on each Edge). */
  reachable?: boolean
  /** Human-readable probe outcome (Kubernetes version, error, or timeout). */
  reachability_message?: string
  /** Probe wall-clock duration in milliseconds. */
  reachability_latency_ms?: number
}

export async function getRegisteredClusters(): Promise<RegisteredCluster[]> {
  const res = await fetch('/api/v1/hub/clusters')
  if (res.status === 401) {
    return redirectToLogin<RegisteredCluster[]>()
  }
  if (!res.ok) {
    // Hub mode may be inactive (412) or the API may have failed. Treat as empty list.
    return []
  }
  const body = await res.json()
  return Array.isArray(body) ? body : []
}

export interface RegisterClusterRequest {
  name: string
  server: string
  bearer_token: string
  ca_data?: string
  insecure?: boolean
  namespaces?: string[]
}

export async function registerCluster(
  req: RegisterClusterRequest,
): Promise<RegisteredCluster> {
  return request('/api/v1/hub/clusters', {
    method: 'POST',
    body: req,
    errorMessage: 'Registration failed',
  })
}

export async function deleteRegisteredCluster(name: string): Promise<boolean> {
  const res = await fetch(`/api/v1/hub/clusters/${encodeURIComponent(name)}`, {
    method: 'DELETE',
  })
  return res.ok
}

export interface RegistrationManifests {
  edge_rbac: string
  extract_commands: string
  hub_secret_template: string
  edge_namespace: string
  hub_namespace: string
  cluster_name: string
}

export interface ManifestParams {
  edgeNamespace?: string
  hubNamespace?: string
  clusterName?: string
}

export async function getRegistrationManifests(
  params: ManifestParams = {},
): Promise<RegistrationManifests> {
  const qs = new URLSearchParams()
  if (params.edgeNamespace) qs.set('edge_namespace', params.edgeNamespace)
  if (params.hubNamespace) qs.set('hub_namespace', params.hubNamespace)
  if (params.clusterName) qs.set('cluster_name', params.clusterName)
  const suffix = qs.toString() ? `?${qs.toString()}` : ''
  return request(`/api/v1/hub/manifests${suffix}`, {
    errorMessage: 'Failed to fetch manifests',
  })
}

export async function updateNotes(
  cluster: string,
  reportType: ReportType,
  namespace: string,
  name: string,
  notes: string,
): Promise<boolean> {
  const response = await fetch(
    `/api/v1/reports/${encodeURIComponent(cluster)}/${encodeURIComponent(reportType)}/${encodeURIComponent(namespace)}/${encodeURIComponent(name)}/notes`,
    {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ notes }),
    },
  )
  return response.ok
}
