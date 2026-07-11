import { useEffect, useRef, useState, useCallback } from 'react'

export function usePolling<T>(
  fetcher: () => Promise<T>,
  intervalMs: number,
  enabled = true,
): { data: T | null; error: unknown; refresh: () => void } {
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState<unknown>(null)
  const mountedRef = useRef(true)

  const refresh = useCallback(() => {
    fetcher()
      .then((result) => {
        if (mountedRef.current) {
          setData(result)
          setError(null)
        }
      })
      .catch((err) => {
        console.error('[trivy-viewer] polling failed', err)
        if (mountedRef.current) setError(err)
      })
  }, [fetcher])

  useEffect(() => {
    mountedRef.current = true
    refresh()

    if (!enabled) return
    const id = setInterval(refresh, intervalMs)
    return () => {
      mountedRef.current = false
      clearInterval(id)
    }
  }, [refresh, intervalMs, enabled])

  return { data, error, refresh }
}
