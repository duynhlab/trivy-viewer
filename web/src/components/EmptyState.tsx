import { Link } from 'react-router-dom'
import styles from './EmptyState.module.css'

export interface EmptyStateAction {
  label: string
  to?: string
  onClick?: () => void
}

interface EmptyStateProps {
  icon?: string
  title: string
  description: string
  action?: EmptyStateAction
  secondaryAction?: EmptyStateAction
}

export default function EmptyState({
  icon = 'fa-inbox',
  title,
  description,
  action,
  secondaryAction,
}: EmptyStateProps) {
  return (
    <div className={styles.wrap} role="status">
      <i className={`fa-solid ${icon} ${styles.icon}`} aria-hidden="true" />
      <h3 className={styles.title}>{title}</h3>
      <p className={styles.description}>{description}</p>
      {(action || secondaryAction) && (
        <div className={styles.actions}>
          {action && (
            action.to ? (
              <Link to={action.to} className="btn-primary">{action.label}</Link>
            ) : (
              <button type="button" className="btn-primary" onClick={action.onClick}>
                {action.label}
              </button>
            )
          )}
          {secondaryAction && (
            secondaryAction.to ? (
              <Link to={secondaryAction.to} className="btn-secondary">{secondaryAction.label}</Link>
            ) : (
              <button type="button" className="btn-secondary" onClick={secondaryAction.onClick}>
                {secondaryAction.label}
              </button>
            )
          )}
        </div>
      )}
    </div>
  )
}
