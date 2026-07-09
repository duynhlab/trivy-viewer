import type { ReactNode } from 'react'
import styles from './EmptyState.module.css'

interface OnboardingBannerProps {
  title: string
  children: ReactNode
}

export function OnboardingBanner({ title, children }: OnboardingBannerProps) {
  return (
    <div className={styles.banner} role="note">
      <i className={`fa-solid fa-circle-info ${styles.bannerIcon}`} aria-hidden="true" />
      <div>
        <p className={styles.bannerTitle}>{title}</p>
        <p className={styles.bannerText}>{children}</p>
      </div>
    </div>
  )
}

interface ErrorBannerProps {
  message: string
}

export function ErrorBanner({ message }: ErrorBannerProps) {
  return (
    <div className={styles.errorBanner} role="alert">
      <i className={`fa-solid fa-triangle-exclamation ${styles.bannerIcon}`} aria-hidden="true" />
      <div>
        <p className={styles.bannerTitle}>Failed to load data</p>
        <p className={styles.bannerText}>{message}</p>
      </div>
    </div>
  )
}
