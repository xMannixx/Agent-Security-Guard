// Agent Security Guard — Hermes Desktop half.
//
// Read only. Shows what the guard asked about, blocked and allowed, with the
// reason in plain words, and whether its audit trail holds. It changes no
// setting and never answers an approval: that stays with you, in Hermes's own
// prompt. Data comes from this plugin's backend (dashboard/plugin_api.py) over
// ctx.rest, polled every few seconds.
//
// Plain ESM, loaded uncompiled: jsx()/jsxs() instead of JSX syntax, and only
// @hermes/plugin-sdk, react and react/jsx-runtime are imported.

import {
  Badge,
  Button,
  Codicon,
  ConfirmDialog,
  EmptyState,
  ErrorState,
  Loader,
  PALETTE_AREA,
  ROUTES_AREA,
  SIDEBAR_NAV_AREA,
  SegmentedControl,
  Tip,
  host,
  relativeTime,
  useI18n,
  useQuery,
  useQueryClient
} from '@hermes/plugin-sdk'
import { useState } from 'react'
import { jsx, jsxs } from 'react/jsx-runtime'

const ID = 'agent-security-guard-plugin'
const PATH = '/security-guard'
const POLL_MS = 5000

// --------------------------------------------------------------------------
// Words
// --------------------------------------------------------------------------

const TEXT = {
  en: {
    title: 'Security Guard',
    subtitle: 'What your agent read cannot decide what it does.',
    nav: 'Security Guard',
    open: 'Open Security Guard',
    asked: 'Asked you',
    blocked: 'Blocked',
    allowed: 'Allowed',
    today: 'today',
    mode: 'Mode',
    modes: {
      strict: 'Strict',
      'autonomous-safe': 'Standard',
      monitor: 'Monitor only'
    },
    modeHelp: {
      strict: 'Also asks about tools it does not know.',
      'autonomous-safe': 'Stops the dangerous cases: a shell, install or send-out after outside content, secrets leaving, self-changes.',
      monitor: 'Stops nothing. It only records what it would have done.'
    },
    modeFromEnv: 'set by AGENT_SECURITY_GUARD_MODE',
    modeLocked: 'Locked',
    modeChangeRow: (from, to) => `Mode changed from ${from} to ${to}.`,
    modeChanged: mode => `Security Guard: mode is now ${mode}`,
    modeFailed: 'The mode could not be changed',
    confirmTitle: mode => `Switch to “${mode}”?`,
    confirmMonitor: 'The guard then stops nothing: a web page could make your agent run commands or send data out. Use this only to try something out, and switch back afterwards.',
    confirmWeaker: 'The guard will then ask about fewer things.',
    confirmButton: 'Switch',
    cancel: 'Cancel',
    attention: 'Asked or blocked',
    all: 'All',
    recent: 'Recent decisions',
    none: 'Nothing asked or blocked yet',
    noneAll: 'No decisions yet',
    noneHint: 'Every tool call your agent makes is checked and listed here.',
    after: 'after outside content from',
    trail: 'Audit trail',
    trailHint: 'Every decision is recorded with the hash of the one before it. A changed, removed or inserted record breaks the chain.',
    verify: 'Check the trail',
    checking: 'Checking…',
    intact: 'Intact',
    broken: 'Broken',
    records: 'records',
    noTrail: 'No trail yet.',
    unreachable: 'The guard backend is not reachable',
    unreachableHint: 'Add agent-security-guard-plugin to plugins.enabled in config.yaml and restart Hermes.',
    configError: 'guard.yaml could not be read; the built-in defaults are in force',
    readOnly: 'Approvals stay in Hermes’s own prompt. Every mode change is recorded in the audit trail.',
    chip: 'Security Guard: asked or blocked today'
  },
  de: {
    title: 'Security Guard',
    subtitle: 'Was dein Agent liest, entscheidet nicht, was er tut.',
    nav: 'Security Guard',
    open: 'Security Guard öffnen',
    asked: 'Nachgefragt',
    blocked: 'Blockiert',
    allowed: 'Erlaubt',
    today: 'heute',
    mode: 'Modus',
    modes: {
      strict: 'Streng',
      'autonomous-safe': 'Standard',
      monitor: 'Nur beobachten'
    },
    modeHelp: {
      strict: 'Fragt zusätzlich bei Werkzeugen nach, die er nicht kennt.',
      'autonomous-safe': 'Stoppt die gefährlichen Fälle: Shell, Installation oder Versand nach fremdem Inhalt, Geheimnisse nach außen, Selbstveränderung.',
      monitor: 'Stoppt nichts. Er schreibt nur auf, was er getan hätte.'
    },
    modeFromEnv: 'gesetzt über AGENT_SECURITY_GUARD_MODE',
    modeLocked: 'Gesperrt',
    modeChangeRow: (from, to) => `Modus geändert von ${from} auf ${to}.`,
    modeChanged: mode => `Security Guard: Modus ist jetzt ${mode}`,
    modeFailed: 'Der Modus konnte nicht geändert werden',
    confirmTitle: mode => `Auf „${mode}“ umschalten?`,
    confirmMonitor: 'Dann stoppt der Guard nichts mehr: Eine Webseite könnte deinen Agenten Befehle ausführen oder Daten verschicken lassen. Nur zum Ausprobieren nutzen und danach zurückschalten.',
    confirmWeaker: 'Der Guard fragt dann bei weniger Dingen nach.',
    confirmButton: 'Umschalten',
    cancel: 'Abbrechen',
    attention: 'Nachgefragt oder blockiert',
    all: 'Alle',
    recent: 'Letzte Entscheidungen',
    none: 'Noch nichts nachgefragt oder blockiert',
    noneAll: 'Noch keine Entscheidungen',
    noneHint: 'Jeder Werkzeugaufruf deines Agenten wird geprüft und hier aufgeführt.',
    after: 'nach fremdem Inhalt von',
    trail: 'Protokoll',
    trailHint: 'Jede Entscheidung wird mit dem Fingerabdruck der vorigen gespeichert. Ein geänderter, gelöschter oder eingeschobener Eintrag bricht die Kette.',
    verify: 'Protokoll prüfen',
    checking: 'Prüfe…',
    intact: 'Unverändert',
    broken: 'Verändert',
    records: 'Einträge',
    noTrail: 'Noch kein Protokoll.',
    unreachable: 'Das Guard-Backend ist nicht erreichbar',
    unreachableHint: 'agent-security-guard-plugin in config.yaml unter plugins.enabled eintragen und Hermes neu starten.',
    configError: 'guard.yaml war nicht lesbar; es gelten die eingebauten Regeln',
    readOnly: 'Freigaben bleiben in Hermes’ eigener Abfrage. Jede Modus-Änderung steht im Protokoll.',
    chip: 'Security Guard: heute nachgefragt oder blockiert'
  }
}

// Plain words for the reasons people meet most. Anything else shows the
// guard's own message.
const REASONS = {
  UNTRUSTED_CONTENT_IN_CONTEXT: {
    en: 'Content from outside (a web page, search results) was read earlier in this turn and may have proposed this.',
    de: 'Vorher in dieser Runde wurde fremder Inhalt gelesen (Webseite, Suchergebnis), der das vorgeschlagen haben könnte.'
  },
  SELF_MODIFICATION_REQUIRES_EXPLICIT_USER_ORDER: {
    en: 'The agent wanted to change its own skills, rules or the guard. That needs your explicit go.',
    de: 'Der Agent wollte seine eigenen Fähigkeiten, Regeln oder den Guard ändern. Dafür braucht es dein ausdrückliches Ja.'
  },
  SECRET_EXTERNAL_SEND: {
    en: 'A secret (key, password, token) was about to leave the machine.',
    de: 'Ein Geheimnis (Schlüssel, Passwort, Token) sollte den Rechner verlassen.'
  },
  SECRET_THEN_EXFIL: {
    en: 'A secret was read in this turn, and now something was to be sent out.',
    de: 'In dieser Runde wurde ein Geheimnis gelesen, und jetzt sollte etwas hinausgeschickt werden.'
  },
  UNTRUSTED_TO_SHELL: {
    en: 'Outside content tried to have a shell command run.',
    de: 'Fremder Inhalt wollte einen Shell-Befehl ausführen lassen.'
  },
  UNTRUSTED_TO_LOCAL_WRITE: {
    en: 'Outside content tried to have a file written.',
    de: 'Fremder Inhalt wollte eine Datei schreiben lassen.'
  },
  DOWNLOAD_THEN_EXECUTE: {
    en: 'Something downloaded was about to be run.',
    de: 'Etwas Heruntergeladenes sollte ausgeführt werden.'
  },
  INSTALL_FROM_UNTRUSTED: {
    en: 'An install proposed by outside content.',
    de: 'Eine Installation, die fremder Inhalt vorgeschlagen hat.'
  },
  PRIVILEGED_MEMORY_REQUIRES_CONFIRMATION: {
    en: 'A write to the agent’s rules or identity memory.',
    de: 'Ein Eintrag in das Regel- oder Identitätsgedächtnis des Agenten.'
  },
  UNTRUSTED_TO_AUTH_MEMORY: {
    en: 'Outside content tried to write who may authorise what into memory.',
    de: 'Fremder Inhalt wollte ins Gedächtnis schreiben, wer was erlauben darf.'
  },
  EXPLICIT_NO_WRITE_SCOPE_VIOLATION: {
    en: 'You asked for read only in this turn.',
    de: 'Du hattest in dieser Runde nur Lesen erlaubt.'
  },
  GUARD_DEGRADED_DANGEROUS_KIND: {
    en: 'The guard could not evaluate this call and held it back to be safe.',
    de: 'Der Guard konnte den Aufruf nicht prüfen und hat ihn sicherheitshalber zurückgehalten.'
  }
}

function useText() {
  let locale = 'en'
  try {
    locale = String(useI18n().locale || 'en')
  } catch {
    // no i18n context: English
  }
  const lang = locale.toLowerCase().startsWith('de') ? 'de' : 'en'
  return { lang, t: TEXT[lang] }
}

// --------------------------------------------------------------------------
// Data
// --------------------------------------------------------------------------

let rest = null

function useGuard(path, enabled = true) {
  return useQuery({
    queryKey: [ID, path],
    queryFn: () => rest(path),
    refetchInterval: POLL_MS,
    retry: 1,
    enabled
  })
}

const CATEGORY_BADGE = { asked: 'warn', blocked: 'destructive', allowed: 'muted', mode: 'default' }

// --------------------------------------------------------------------------
// Pieces
// --------------------------------------------------------------------------

const muted = { color: 'var(--ui-text-tertiary)' }
const card = {
  border: '1px solid var(--ui-stroke-secondary)',
  borderRadius: '10px',
  padding: '14px 16px'
}

function Count({ label, value, variant }) {
  return jsxs('div', {
    style: { ...card, flex: '1 1 0', minWidth: '120px' },
    children: [
      jsx('div', { style: { fontSize: '1.6rem', fontWeight: 600, lineHeight: 1.1 }, children: String(value) }),
      jsx('div', { style: { marginTop: '4px' }, children: jsx(Badge, { variant, children: label }) })
    ]
  })
}

// relativeTime takes milliseconds. The trail stores ISO times; one that does
// not parse shows nothing rather than breaking the page.
function when(ts, lang) {
  const ms = Date.parse(ts || '')
  if (!Number.isFinite(ms)) {
    return ''
  }
  try {
    return relativeTime(ms, Date.now(), lang)
  } catch {
    return new Date(ms).toLocaleString()
  }
}

// "mode autonomous-safe -> monitor (desktop)" as the page names the modes.
function modeChangeText(message, t) {
  const found = /mode (\S+) -> (\S+)/.exec(message || '')
  if (!found) {
    return message || ''
  }
  const name = mode => (t.modes && t.modes[mode]) || mode
  return t.modeChangeRow(name(found[1]), name(found[2]))
}

function Decision({ item, lang, t }) {
  const modeChange = item.category === 'mode'
  const reason = modeChange
    ? modeChangeText(item.message, t)
    : (REASONS[item.reason_code] && REASONS[item.reason_code][lang]) || item.message || item.reason_code
  return jsxs('div', {
    style: { display: 'flex', gap: '12px', padding: '10px 0', borderTop: '1px solid var(--ui-stroke-secondary)' },
    children: [
      jsx('div', {
        style: { width: '108px', flex: '0 0 auto' },
        children: jsx(Badge, { variant: CATEGORY_BADGE[item.category] || 'muted', children: t[item.category] || item.category })
      }),
      jsxs('div', {
        style: { minWidth: 0, flex: '1 1 auto' },
        children: [
          jsxs('div', {
            style: { display: 'flex', gap: '8px', alignItems: 'baseline', flexWrap: 'wrap' },
            children: [
              modeChange ? null : jsx('code', { style: { fontWeight: 600 }, children: item.tool || '?' }),
              item.after_outside_tool
                ? jsx('span', { style: { ...muted, fontSize: '0.8rem' }, children: `${t.after} ${item.after_outside_tool}` })
                : null
            ]
          }),
          jsx('div', { style: { fontSize: '0.85rem', marginTop: '2px' }, children: reason }),
          jsx('div', {
            style: { ...muted, fontSize: '0.75rem', marginTop: '2px' },
            children: jsx(Tip, { label: item.reason_code || '', children: jsx('span', { children: when(item.ts, lang) }) })
          })
        ]
      })
    ]
  })
}

function Trail({ t }) {
  const [check, setCheck] = useState({ state: 'idle' })
  const run = () => {
    setCheck({ state: 'running' })
    rest('/verify').then(
      result => setCheck({ state: 'done', result }),
      error => setCheck({ state: 'error', error: String((error && error.message) || error) })
    )
  }
  let outcome = null
  if (check.state === 'done') {
    const r = check.result || {}
    outcome = !r.present
      ? jsx('span', { style: muted, children: t.noTrail })
      : jsxs('span', {
          style: { display: 'inline-flex', gap: '8px', alignItems: 'center' },
          children: [
            jsx(Badge, { variant: r.ok ? 'success' : 'destructive', children: r.ok ? `✓ ${t.intact}` : `✗ ${t.broken}` }),
            jsx('span', { style: muted, children: `${r.records} ${t.records}` }),
            r.problem ? jsx('span', { children: r.problem }) : null
          ]
        })
  } else if (check.state === 'error') {
    outcome = jsx('span', { children: check.error })
  }
  return jsxs('div', {
    style: card,
    children: [
      jsx('div', { style: { fontWeight: 600 }, children: t.trail }),
      jsx('div', { style: { ...muted, fontSize: '0.8rem', margin: '4px 0 10px' }, children: t.trailHint }),
      jsxs('div', {
        style: { display: 'flex', gap: '12px', alignItems: 'center', flexWrap: 'wrap' },
        children: [
          jsx(Button, {
            variant: 'secondary',
            size: 'sm',
            disabled: check.state === 'running',
            onClick: run,
            children: check.state === 'running' ? t.checking : t.verify
          }),
          outcome
        ]
      })
    ]
  })
}

const MODE_ORDER = ['monitor', 'autonomous-safe', 'strict']

function ModeSwitch({ s, t }) {
  const queryClient = useQueryClient()
  const [pending, setPending] = useState(null)
  const label = mode => (t.modes && t.modes[mode]) || mode

  const apply = async mode => {
    const result = await host.request(`plugin.${ID}.mode.set`, { mode })
    if (result && result.error) {
      throw new Error(result.error)
    }
    host.notify({ kind: 'success', message: t.modeChanged(label(mode)) })
    queryClient.invalidateQueries({ queryKey: [ID] })
  }

  const choose = mode => {
    if (mode === s.mode) {
      return
    }
    if (MODE_ORDER.indexOf(mode) < MODE_ORDER.indexOf(s.mode)) {
      setPending(mode)  // weaker: ask first
      return
    }
    apply(mode).catch(error => host.notify({ kind: 'error', message: `${t.modeFailed}: ${(error && error.message) || error}` }))
  }

  const locked = s.mode_locked || s.mode_source === 'env'
  return jsxs('div', {
    style: { display: 'flex', flexDirection: 'column', gap: '4px' },
    children: [
      jsxs('div', {
        style: { display: 'flex', gap: '10px', alignItems: 'center', flexWrap: 'wrap' },
        children: [
          jsx('span', { style: { ...muted, fontSize: '0.8rem' }, children: t.mode }),
          locked
            ? jsx(Tip, {
                label: s.mode_locked || t.modeFromEnv,
                children: jsx(Badge, { variant: 'outline', children: `${label(s.mode)} · ${t.modeLocked}` })
              })
            : jsx(SegmentedControl, {
                value: s.mode,
                onChange: choose,
                sizing: 'content',
                options: MODE_ORDER.slice().reverse().map(mode => ({ id: mode, label: label(mode) }))
              })
        ]
      }),
      jsx('div', {
        style: s.mode === 'monitor' ? { fontSize: '0.8rem', color: 'var(--ui-accent)' } : { ...muted, fontSize: '0.8rem' },
        children: (t.modeHelp && t.modeHelp[s.mode]) || ''
      }),
      jsx(ConfirmDialog, {
        open: pending !== null,
        onClose: () => setPending(null),
        onConfirm: () => apply(pending),
        dismissOnConfirm: true,
        destructive: pending === 'monitor',
        title: t.confirmTitle(label(pending)),
        description: pending === 'monitor' ? t.confirmMonitor : t.confirmWeaker,
        confirmLabel: t.confirmButton,
        cancelLabel: t.cancel
      })
    ]
  })
}

function Page() {
  const { lang, t } = useText()
  const [scope, setScope] = useState('attention')
  const status = useGuard('/status')
  const list = useGuard(scope === 'all' ? '/decisions?all=1&limit=100' : '/decisions?limit=100')

  if (status.isError) {
    return jsx('div', {
      style: { padding: '24px' },
      children: jsx(ErrorState, { title: t.unreachable, description: t.unreachableHint })
    })
  }
  if (status.isLoading || !status.data) {
    return jsx('div', { style: { padding: '24px' }, children: jsx(Loader, {}) })
  }

  const s = status.data
  const today = s.today || {}
  const items = (list.data && list.data.decisions) || []

  return jsx('div', {
    style: { height: '100%', overflow: 'auto' },
    children: jsxs('div', {
      style: { maxWidth: '880px', margin: '0 auto', padding: '24px', display: 'flex', flexDirection: 'column', gap: '16px' },
      children: [
        jsxs('div', {
          children: [
            jsxs('div', {
              style: { display: 'flex', gap: '10px', alignItems: 'center', flexWrap: 'wrap' },
              children: [
                jsx(Codicon, { name: 'shield' }),
                jsx('h1', { style: { fontSize: '1.25rem', fontWeight: 600, margin: 0 }, children: t.title }),
                s.version ? jsx('span', { style: { ...muted, fontSize: '0.8rem' }, children: `v${s.version}` }) : null
              ]
            }),
            jsx('div', { style: { ...muted, fontSize: '0.85rem', marginTop: '4px' }, children: t.subtitle }),
            jsx('div', { style: { marginTop: '12px' }, children: jsx(ModeSwitch, { s, t }) }),
            s.config_error ? jsx('div', { style: { fontSize: '0.8rem', marginTop: '4px' }, children: jsx(Badge, { variant: 'destructive', children: t.configError }) }) : null
          ]
        }),
        jsxs('div', {
          style: { display: 'flex', gap: '12px', flexWrap: 'wrap' },
          children: [
            jsx(Count, { label: `${t.asked} ${t.today}`, value: today.asked || 0, variant: 'warn' }),
            jsx(Count, { label: `${t.blocked} ${t.today}`, value: today.blocked || 0, variant: 'destructive' }),
            jsx(Count, { label: `${t.allowed} ${t.today}`, value: today.allowed || 0, variant: 'muted' })
          ]
        }),
        jsxs('div', {
          style: card,
          children: [
            jsxs('div', {
              style: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '12px', flexWrap: 'wrap', marginBottom: '6px' },
              children: [
                jsx('div', { style: { fontWeight: 600 }, children: t.recent }),
                jsx(SegmentedControl, {
                  value: scope,
                  onChange: setScope,
                  sizing: 'content',
                  options: [
                    { id: 'attention', label: t.attention },
                    { id: 'all', label: t.all }
                  ]
                })
              ]
            }),
            list.isError
              ? jsx(ErrorState, { title: t.unreachable, description: String((list.error && list.error.message) || '') })
              : items.length === 0
              ? jsx(EmptyState, { title: scope === 'all' ? t.noneAll : t.none, description: t.noneHint })
              : jsx('div', { children: items.map((item, i) => jsx(Decision, { item, lang, t }, `${item.ts}-${i}`)) })
          ]
        }),
        jsx(Trail, { t }),
        jsx('div', { style: { ...muted, fontSize: '0.75rem' }, children: t.readOnly })
      ]
    })
  })
}

function Chip() {
  const { t } = useText()
  const status = useGuard('/status')
  if (!status.data) {
    return null
  }
  const today = status.data.today || {}
  const flagged = (today.asked || 0) + (today.blocked || 0)
  const monitor = status.data.mode === 'monitor'
  return jsx(Tip, {
    label: monitor ? `${t.title}: ${t.modes.monitor}` : t.chip,
    children: jsxs('button', {
      type: 'button',
      onClick: () => host.navigate(PATH),
      style: {
        display: 'inline-flex',
        alignItems: 'center',
        gap: '4px',
        height: '100%',
        padding: '0 6px',
        fontSize: '0.6875rem',
        color: monitor ? 'var(--ui-accent)' : 'var(--ui-text-tertiary)',
        background: 'transparent',
        border: 0,
        cursor: 'pointer'
      },
      children: [jsx(Codicon, { name: 'shield' }), jsx('span', { children: String(flagged) })]
    })
  })
}

export default {
  id: ID,
  name: 'Security Guard',
  register(ctx) {
    rest = ctx.rest
    ctx.registerMany([
      { id: 'page', area: ROUTES_AREA, data: { path: PATH }, render: () => jsx(Page, {}) },
      { id: 'nav', area: SIDEBAR_NAV_AREA, data: { path: PATH, label: 'Security Guard', codicon: 'shield' } },
      { id: 'chip', area: 'statusBar.right', order: 105, render: () => jsx(Chip, {}) },
      {
        id: 'open',
        area: PALETTE_AREA,
        data: {
          id: `${ID}.open`,
          label: 'Open Security Guard',
          keywords: ['security', 'guard', 'audit', 'injection'],
          run: () => host.navigate(PATH)
        }
      }
    ])
  }
}
