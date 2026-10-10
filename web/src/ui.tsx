import React, { useEffect, useState } from 'react'
import { Circle, CircleAlert, CircleCheck, CircleHelp, CircleMinus, CircleStop, CircleX, Info, LoaderCircle, Monitor, Moon, OctagonAlert, ShieldAlert, Sun, TriangleAlert } from 'lucide-react'

export const severityMeta: Record<string, {label: string; icon: React.ElementType}> = {
  critical: {label: 'Critical', icon: OctagonAlert},
  high: {label: 'High', icon: ShieldAlert},
  medium: {label: 'Medium', icon: TriangleAlert},
  low: {label: 'Low', icon: CircleAlert},
  info: {label: 'Info', icon: Info},
  unknown: {label: 'Unknown', icon: CircleHelp},
}

export const stateMeta: Record<string, {label: string; icon: React.ElementType}> = {
  completed: {label: 'Completed', icon: CircleCheck},
  partial: {label: 'Partial', icon: CircleAlert},
  failed: {label: 'Failed', icon: CircleX},
  skipped: {label: 'Skipped', icon: CircleMinus},
  cancelled: {label: 'Stopped', icon: CircleStop},
  not_run: {label: 'Not run', icon: CircleMinus},
  pending: {label: 'Waiting', icon: Circle},
  running: {label: 'Running', icon: LoaderCircle},
  queued: {label: 'Queued', icon: Circle},
}

export function SeverityBadge({level, compact = false}: {level: string; compact?: boolean}) {
  const meta = severityMeta[level] ?? severityMeta.unknown
  return <span className={`badge sev sev-${severityMeta[level] ? level : 'unknown'}${compact ? ' compact' : ''}`}><meta.icon size={13} aria-hidden="true"/>{!compact && meta.label}</span>
}

export function SeverityIcon({level}: {level: string}) {
  const meta = severityMeta[level] ?? severityMeta.unknown
  return <span className={`sev-icon sev-${severityMeta[level] ? level : 'unknown'}`} aria-hidden="true"><meta.icon size={16}/></span>
}

export function StateBadge({state}: {state: string}) {
  const meta = stateMeta[state] ?? {label: state, icon: Circle}
  return <span className={`badge state state-${state}`}><meta.icon size={13} className={state === 'running' ? 'spin' : undefined} aria-hidden="true"/>{meta.label}</span>
}

export function StateIcon({state, size = 16}: {state: string; size?: number}) {
  const meta = stateMeta[state] ?? {label: state, icon: Circle}
  return <span className={`state-icon state-${state}`} aria-hidden="true"><meta.icon size={size} className={state === 'running' ? 'spin' : undefined}/></span>
}

export function PageHeader({title, description, actions}: {title: string; description: string; actions?: React.ReactNode}) {
  return <header className="page-header"><div><h1>{title}</h1><p>{description}</p></div>{actions && <div className="page-actions">{actions}</div>}</header>
}

export function Panel({title, icon: Icon, meta, children, className = ''}: {title: string; icon?: React.ElementType; meta?: React.ReactNode; children: React.ReactNode; className?: string}) {
  return <section className={`panel ${className}`}><div className="panel-head"><h2>{Icon && <Icon size={16} aria-hidden="true"/>}{title}</h2>{meta && <span className="panel-meta">{meta}</span>}</div>{children}</section>
}

export function EmptyState({icon: Icon, title, children}: {icon: React.ElementType; title: string; children?: React.ReactNode}) {
  return <div className="empty"><span className="empty-icon"><Icon size={20} aria-hidden="true"/></span><strong>{title}</strong>{children && <p>{children}</p>}</div>
}

export function Stat({label, value, hint, icon: Icon, tone}: {label: string; value: React.ReactNode; hint?: React.ReactNode; icon: React.ElementType; tone?: string}) {
  return <div className={`stat${tone ? ` tone-${tone}` : ''}`}><div className="stat-top"><span>{label}</span><Icon size={16} aria-hidden="true"/></div><strong>{value}</strong>{hint && <small>{hint}</small>}</div>
}

export function Meter({value, label}: {value: number; label: string}) {
  return <div className="meter" role="progressbar" aria-label={label} aria-valuemin={0} aria-valuemax={100} aria-valuenow={value}><div style={{width: `${value}%`}}/></div>
}

type Theme = 'system' | 'light' | 'dark'
const themeIcons: Record<Theme, React.ElementType> = {system: Monitor, light: Sun, dark: Moon}

function storedTheme(): Theme {
  try {
    const value = localStorage.getItem('projectn-theme')
    return value === 'light' || value === 'dark' ? value : 'system'
  } catch {
    return 'system'
  }
}

export function ThemeToggle() {
  const [theme, setTheme] = useState<Theme>(storedTheme)
  useEffect(() => {
    if (theme === 'system') delete document.documentElement.dataset.theme
    else document.documentElement.dataset.theme = theme
    try {
      if (theme === 'system') localStorage.removeItem('projectn-theme')
      else localStorage.setItem('projectn-theme', theme)
    } catch { /* storage can be unavailable; the choice then lasts for this page only */ }
  }, [theme])
  return <div className="theme-toggle" role="radiogroup" aria-label="Theme">{(Object.keys(themeIcons) as Theme[]).map(option => {
    const Icon = themeIcons[option]
    return <button key={option} type="button" role="radio" aria-checked={theme === option} aria-label={`${option[0].toUpperCase()}${option.slice(1)} theme`} title={`${option[0].toUpperCase()}${option.slice(1)} theme`} className={theme === option ? 'on' : ''} onClick={() => setTheme(option)}><Icon size={14} aria-hidden="true"/></button>
  })}</div>
}
