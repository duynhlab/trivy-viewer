import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  createToken,
  getRegisteredClusters,
  getStats,
  registerCluster,
} from './api'

// Pin the request-helper semantics every endpoint relies on: 401 redirects
// to login, non-OK statuses throw the server's error message, and the
// deliberate deviations (hub cluster list tolerating 412) stay intact.

function mockFetch(status: number, body: unknown) {
  const response = {
    ok: status >= 200 && status < 300,
    status,
    json: () => Promise.resolve(body),
  } as Response
  const fn = vi.fn(() => Promise.resolve(response))
  vi.stubGlobal('fetch', fn)
  return fn
}

beforeEach(() => {
  // window.location.href is assigned on 401; make it writable in jsdom.
  Object.defineProperty(window, 'location', {
    value: { pathname: '/vulnerabilities', href: '' },
    writable: true,
  })
})

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('request helper via getStats', () => {
  it('parses JSON on success', async () => {
    mockFetch(200, { total_clusters: 2 })
    await expect(getStats()).resolves.toEqual({ total_clusters: 2 })
  })

  it('redirects to login with return_to on 401 and never resolves', async () => {
    mockFetch(401, {})
    const settled = vi.fn()
    void getStats().then(settled, settled)
    await new Promise((r) => setTimeout(r, 10))
    expect(settled).not.toHaveBeenCalled()
    expect(window.location.href).toBe('/auth/login?return_to=%2Fvulnerabilities')
  })

  it('throws the server error message on non-OK', async () => {
    mockFetch(500, { error: 'db locked' })
    await expect(getStats()).rejects.toThrow('db locked')
  })

  it('falls back to HTTP status when the error body is empty', async () => {
    const response = {
      ok: false,
      status: 502,
      json: () => Promise.reject(new Error('not json')),
    } as unknown as Response
    vi.stubGlobal('fetch', vi.fn(() => Promise.resolve(response)))
    await expect(getStats()).rejects.toThrow('HTTP 502')
  })
})

describe('mutations', () => {
  it('createToken posts JSON and uses its fallback message', async () => {
    const fn = mockFetch(400, {})
    await expect(createToken('ci', 'desc', 30)).rejects.toThrow('Failed to create token')
    const [url, init] = fn.mock.calls[0] as unknown as [string, RequestInit]
    expect(url).toBe('/api/v1/auth/tokens')
    expect(init.method).toBe('POST')
    expect(JSON.parse(init.body as string)).toEqual({
      name: 'ci',
      description: 'desc',
      expires_days: 30,
    })
  })

  it('registerCluster surfaces the server error', async () => {
    mockFetch(400, { error: 'invalid CA data' })
    await expect(
      registerCluster({ name: 'e', server: 'https://x', bearer_token: 't' }),
    ).rejects.toThrow('invalid CA data')
  })
})

describe('getRegisteredClusters deviations', () => {
  it('returns [] when hub mode is inactive (412)', async () => {
    mockFetch(412, { error: 'no kube access' })
    await expect(getRegisteredClusters()).resolves.toEqual([])
  })

  it('returns [] for a non-array body', async () => {
    mockFetch(200, { unexpected: true })
    await expect(getRegisteredClusters()).resolves.toEqual([])
  })

  it('passes through an array body', async () => {
    mockFetch(200, [{ name: 'edge-a' }])
    await expect(getRegisteredClusters()).resolves.toEqual([{ name: 'edge-a' }])
  })
})
