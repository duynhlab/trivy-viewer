import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, renderHook } from '@testing-library/react'
import { usePolling } from './usePolling'

beforeEach(() => {
  vi.useFakeTimers()
  vi.spyOn(console, 'error').mockImplementation(() => {})
})

afterEach(() => {
  vi.useRealTimers()
  vi.restoreAllMocks()
})

describe('usePolling', () => {
  it('fetches immediately and then on the interval', async () => {
    let n = 0
    const fetcher = vi.fn(() => Promise.resolve(++n))
    const { result } = renderHook(() => usePolling(fetcher, 1000))

    await act(async () => {})
    expect(result.current.data).toBe(1)

    await act(async () => {
      vi.advanceTimersByTime(1000)
    })
    expect(fetcher).toHaveBeenCalledTimes(2)
    expect(result.current.data).toBe(2)
  })

  it('exposes the error and clears it on the next success', async () => {
    let fail = true
    const fetcher = vi.fn(() =>
      fail ? Promise.reject(new Error('boom')) : Promise.resolve('ok'),
    )
    const { result } = renderHook(() => usePolling(fetcher, 1000))

    await act(async () => {})
    expect((result.current.error as Error).message).toBe('boom')
    expect(result.current.data).toBeNull()

    fail = false
    await act(async () => {
      vi.advanceTimersByTime(1000)
    })
    expect(result.current.error).toBeNull()
    expect(result.current.data).toBe('ok')
  })

  it('stops polling and ignores late results after unmount', async () => {
    const fetcher = vi.fn(() => Promise.resolve('x'))
    const { unmount } = renderHook(() => usePolling(fetcher, 1000))

    await act(async () => {})
    unmount()

    vi.advanceTimersByTime(5000)
    expect(fetcher).toHaveBeenCalledTimes(1)
  })

  it('does not schedule an interval when disabled', async () => {
    const fetcher = vi.fn(() => Promise.resolve('x'))
    renderHook(() => usePolling(fetcher, 1000, false))

    await act(async () => {})
    vi.advanceTimersByTime(5000)
    expect(fetcher).toHaveBeenCalledTimes(1) // initial fetch only
  })
})
