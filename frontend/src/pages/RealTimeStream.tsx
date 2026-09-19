import React, { useState, useEffect, useRef } from 'react'
import { Link } from 'react-router-dom'
import {
  Radio,
  Wifi,
  WifiOff,
  AlertTriangle,
  Shield,
  Zap,
  Play,
  Trash2,
  ExternalLink,
  Copy,
  Check,
  RefreshCw,
  Mail,
  Flame,
  Bug,
  Lock,
  ArrowRight,
} from 'lucide-react'
import {
  getThreatStreamWsUrl,
  getGoogleIngestionStatus,
  registerMailboxWatch,
  stopMailboxWatch,
  simulateRealtimeIngestion,
  broadcastTestAlert,
} from '../services/api'

interface ThreatStreamEvent {
  id: string
  timestamp: string
  type: string
  source?: string
  data?: any
  isSimulated?: boolean
}

export default function RealTimeStream() {
  const [isConnected, setIsConnected] = useState(false)
  const [isConnecting, setIsConnecting] = useState(true)
  const [events, setEvents] = useState<ThreatStreamEvent[]>([])
  const [activeClients, setActiveClients] = useState<number>(0)
  const [simulating, setSimulating] = useState(false)
  const [copiedWebhook, setCopiedWebhook] = useState(false)
  const [watchEmail, setWatchEmail] = useState('')
  const [customTopic, setCustomTopic] = useState('')
  const [showAdvancedGcp, setShowAdvancedGcp] = useState(false)
  const [watchNotification, setWatchNotification] = useState<{ type: 'success' | 'error'; message: string } | null>(null)
  const [watchLoading, setWatchLoading] = useState(false)
  const [watchStatus, setWatchStatus] = useState<any>(null)

  const socketRef = useRef<WebSocket | null>(null)
  const reconnectTimeoutRef = useRef<any>(null)

  const webhookUrl = `${window.location.origin}/api/v1/webhook/google-pubsub`
  const wsUrl = getThreatStreamWsUrl()

  // Load Watch Manager Status
  const fetchWatchStatus = async () => {
    try {
      const data = await getGoogleIngestionStatus()
      setWatchStatus(data)
    } catch {
      // Backend may be offline or in fallback mode
    }
  }

  useEffect(() => {
    fetchWatchStatus()
    const interval = setInterval(fetchWatchStatus, 15000)
    return () => clearInterval(interval)
  }, [])

  // WebSocket Connection Lifecycle
  const connectWebSocket = () => {
    setIsConnecting(true)
    try {
      const ws = new WebSocket(wsUrl)
      socketRef.current = ws

      ws.onopen = () => {
        setIsConnected(true)
        setIsConnecting(false)
      }

      ws.onmessage = (message) => {
        try {
          const parsed = JSON.parse(message.data)

          if (parsed.event === 'connected') {
            return
          }

          if (parsed.type === 'threat_analysis' || parsed.type === 'system_broadcast') {
            const newEvent: ThreatStreamEvent = {
              id: parsed.data?.email_id || Math.random().toString(36).substring(7),
              timestamp: parsed.timestamp || new Date().toISOString(),
              type: parsed.type,
              source: parsed.source || 'google_workspace',
              data: parsed.data || parsed,
            }
            setEvents((prev) => [newEvent, ...prev.slice(0, 49)])
          }
        } catch {
          // Non-JSON ping/pong
        }
      }

      ws.onclose = () => {
        setIsConnected(false)
        setIsConnecting(false)
        // Auto-reconnect after 3 seconds
        reconnectTimeoutRef.current = setTimeout(() => {
          connectWebSocket()
        }, 3000)
      }

      ws.onerror = () => {
        setIsConnected(false)
        setIsConnecting(false)
      }
    } catch {
      setIsConnected(false)
      setIsConnecting(false)
    }
  }

  useEffect(() => {
    connectWebSocket()
    return () => {
      if (reconnectTimeoutRef.current) clearTimeout(reconnectTimeoutRef.current)
      if (socketRef.current) socketRef.current.close()
    }
  }, [])

  const copyWebhookUrl = () => {
    navigator.clipboard.writeText(webhookUrl)
    setCopiedWebhook(true)
    setTimeout(() => setCopiedWebhook(false), 2000)
  }

  // Preset Simulation Scenarios
  const runSimulation = async (scenario: 'phishing' | 'bec' | 'malware' | 'clean') => {
    setSimulating(true)

    let rawEmail = ''
    let emailUser = 'security-test@company.com'

    if (scenario === 'phishing') {
      rawEmail = `From: security-alert@paypa1-verification.com\nTo: finance@company.com\nSubject: URGENT: Your PayPal Account Has Been Suspended\nDate: ${new Date().toUTCString()}\n\nDear User,\n\nWe detected suspicious activity. Please verify your credentials immediately: http://paypa1-login-update.online/verify?account=98124`
    } else if (scenario === 'bec') {
      rawEmail = `From: "CEO Tim Cook" <ceo-office@apple-executive-hq.com>\nReply-To: secret-personal-desk@gmail.com\nTo: controller@company.com\nSubject: CONFIDENTIAL: Urgent Wire Acquisition ($65,000)\nDate: ${new Date().toUTCString()}\n\nPlease process this vendor acquisition wire transfer immediately before market close.`
    } else if (scenario === 'malware') {
      rawEmail = `From: "DHL Logistics" <dispatch@dhl-delivery-tracking.biz>\nTo: logistics@company.com\nSubject: DHL Package Delivery Notice #99812 - Action Required\nDate: ${new Date().toUTCString()}\n\nPlease extract your shipping manifest: invoice_shipping_manifest.exe`
    } else {
      rawEmail = `From: "Sarah Chen" <sarah.chen@company.com>\nTo: team@company.com\nSubject: Weekly Sprint Retro Notes & Action Items\nDate: ${new Date().toUTCString()}\n\nHi team, attached are the action items from our sprint retrospective today.`
    }

    try {
      const result = await simulateRealtimeIngestion(emailUser, rawEmail)
      // Manually add to events if WebSocket is reconnecting
      if (!isConnected && result.analysis) {
        setEvents((prev) => [
          {
            id: result.email_id,
            timestamp: new Date().toISOString(),
            type: 'threat_analysis',
            source: 'simulate:manual',
            data: result.analysis,
          },
          ...prev,
        ])
      }
    } catch (err: any) {
      alert('Simulation error: ' + (err.message || 'Check backend status'))
    } finally {
      setSimulating(false)
    }
  }

  const handleRegisterWatch = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!watchEmail) return
    setWatchLoading(true)
    setWatchNotification(null)
    try {
      const res = await registerMailboxWatch(watchEmail, customTopic.trim() || undefined)
      const targetEmail = watchEmail
      setWatchEmail('')
      setCustomTopic('')
      fetchWatchStatus()
      const isSim = res?.watch_info?.is_simulated || res?.watch_info?.status?.includes('demo')
      setWatchNotification({
        type: 'success',
        message: isSim
          ? `✓ Active simulated mailbox watch registered for ${targetEmail}. Trigger test events above to observe real-time ingestion!`
          : `✓ Live GCP Pub/Sub mailbox watch registered for ${targetEmail}!`
      })
      setTimeout(() => setWatchNotification(null), 8000)
    } catch (err: any) {
      const msg = err.response?.data?.detail || err.message
      setWatchNotification({
        type: 'error',
        message: `Watch registration failed: ${msg}`
      })
    } finally {
      setWatchLoading(false)
    }
  }

  const handleStopWatch = async (email: string) => {
    try {
      await stopMailboxWatch(email)
      fetchWatchStatus()
      setWatchNotification({
        type: 'success',
        message: `Stopped mailbox watch for ${email}.`
      })
      setTimeout(() => setWatchNotification(null), 5000)
    } catch (err: any) {
      setWatchNotification({
        type: 'error',
        message: 'Failed to stop watch: ' + (err.response?.data?.detail || err.message)
      })
    }
  }

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <div className="flex items-center space-x-3">
            <Radio className="w-8 h-8 text-red-600 animate-pulse" />
            <h1 className="text-3xl font-black tracking-tight text-slate-900">Real-Time Threat Stream</h1>
          </div>
          <p className="text-slate-500 text-sm mt-1">
            Google Workspace / Gmail Event-Driven Ingestion Pipeline & Live WebSocket Broadcast Channel
          </p>
        </div>

        {/* Live WebSocket Status Pill */}
        <div className="flex items-center space-x-3">
          <button
            onClick={() => broadcastTestAlert('SOC Ping Broadcast Test', 'INFO')}
            className="px-3.5 py-2 rounded-lg bg-white hover:bg-slate-50 text-xs font-semibold text-slate-700 transition-colors border border-slate-200 shadow-xs flex items-center space-x-1.5"
          >
            <Zap className="w-3.5 h-3.5 text-amber-500" />
            <span>Send Test Broadcast</span>
          </button>

          <div
            className={`inline-flex items-center px-3.5 py-1.5 rounded-full text-xs font-semibold border shadow-xs ${
              isConnected
                ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                : 'bg-red-50 text-red-700 border-red-200'
            }`}
          >
            {isConnected ? (
              <>
                <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 mr-2 animate-ping" />
                <Wifi className="w-3.5 h-3.5 mr-1.5 text-emerald-600" />
                STREAM ONLINE
              </>
            ) : (
              <>
                <WifiOff className="w-3.5 h-3.5 mr-1.5 text-red-600" />
                {isConnecting ? 'CONNECTING...' : 'STREAM OFFLINE'}
              </>
            )}
          </div>
        </div>
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="card-elevated bg-white p-4">
          <p className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Live Events Streamed</p>
          <p className="text-3xl font-extrabold text-slate-900 mt-1">{events.length}</p>
          <p className="text-xs text-slate-400 mt-1">Captured in current session</p>
        </div>

        <div className="card-elevated bg-white p-4">
          <p className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Critical Threats</p>
          <p className="text-3xl font-extrabold text-red-600 mt-1">
            {events.filter((e) => (e.data?.risk_score || 0) >= 70 || e.data?.is_malicious).length}
          </p>
          <p className="text-xs text-slate-400 mt-1">Requiring immediate response</p>
        </div>

        <div className="card-elevated bg-white p-4">
          <p className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Monitored Mailboxes</p>
          <p className="text-3xl font-extrabold text-slate-800 mt-1">
            {watchStatus?.active_watched_count || 0}
          </p>
          <p className="text-xs text-slate-400 mt-1">Active users().watch()</p>
        </div>

        <div className="card-elevated bg-white p-4">
          <p className="text-xs font-semibold text-slate-500 uppercase tracking-wider">WebSocket Endpoint</p>
          <p className="text-sm font-mono text-emerald-700 font-bold mt-2 truncate">/api/v1/ws/threat-stream</p>
          <p className="text-xs text-slate-400 mt-1">Full duplex broadcast</p>
        </div>
      </div>

      {/* Google Cloud Pub/Sub Push Webhook Panel */}
      <div className="card-elevated bg-white p-6 space-y-5">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 border-b border-slate-200 pb-4">
          <div>
            <h2 className="text-lg font-bold flex items-center space-x-2 text-slate-900">
              <Shield className="w-5 h-5 text-red-600" />
              <span>Google Cloud Pub/Sub Webhook Configuration</span>
            </h2>
            <p className="text-xs text-slate-500 mt-0.5">
              Gmail pushes real-time events to this endpoint whenever new emails land in monitored inboxes
            </p>
          </div>

          <div className="flex items-center space-x-2 bg-slate-50 px-3 py-1.5 rounded-lg border border-slate-200">
            <span className="text-xs font-mono text-slate-700 font-medium truncate max-w-[280px] sm:max-w-md">
              {webhookUrl}
            </span>
            <button
              onClick={copyWebhookUrl}
              className="p-1 text-slate-400 hover:text-slate-700 transition-colors"
              title="Copy Webhook URL"
            >
              {copiedWebhook ? <Check className="w-4 h-4 text-emerald-600" /> : <Copy className="w-4 h-4" />}
            </button>
          </div>
        </div>

        {/* Live Simulator Presets */}
        <div>
          <p className="text-xs font-bold text-slate-700 uppercase tracking-wider mb-2.5">
            Instant Pipeline Test Simulator (Trigger Inbound Threat Ingestion):
          </p>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5">
            <button
              disabled={simulating}
              onClick={() => runSimulation('phishing')}
              className="p-3.5 rounded-xl bg-red-50/70 hover:bg-red-100/80 border border-red-200 text-left transition-all group"
            >
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-red-700 flex items-center space-x-1.5">
                  <Flame className="w-4 h-4 text-red-600" />
                  <span>Credential Phishing</span>
                </span>
                <Play className="w-3.5 h-3.5 text-red-600 opacity-0 group-hover:opacity-100 transition-opacity" />
              </div>
              <p className="text-[11px] text-slate-500 mt-1">Fake PayPal suspension notice & harvester URL</p>
            </button>

            <button
              disabled={simulating}
              onClick={() => runSimulation('bec')}
              className="p-3.5 rounded-xl bg-amber-50/70 hover:bg-amber-100/80 border border-amber-200 text-left transition-all group"
            >
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-amber-800 flex items-center space-x-1.5">
                  <Lock className="w-4 h-4 text-amber-600" />
                  <span>Executive Impersonation</span>
                </span>
                <Play className="w-3.5 h-3.5 text-amber-600 opacity-0 group-hover:opacity-100 transition-opacity" />
              </div>
              <p className="text-[11px] text-slate-500 mt-1">CEO BEC wire transfer spoof with reply-to mismatch</p>
            </button>

            <button
              disabled={simulating}
              onClick={() => runSimulation('malware')}
              className="p-3.5 rounded-xl bg-slate-100/80 hover:bg-slate-200/70 border border-slate-200 text-left transition-all group"
            >
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-slate-800 flex items-center space-x-1.5">
                  <Bug className="w-4 h-4 text-slate-700" />
                  <span>Malware Attachment</span>
                </span>
                <Play className="w-3.5 h-3.5 text-slate-700 opacity-0 group-hover:opacity-100 transition-opacity" />
              </div>
              <p className="text-[11px] text-slate-500 mt-1">Fake shipping dispatch with executable payload</p>
            </button>

            <button
              disabled={simulating}
              onClick={() => runSimulation('clean')}
              className="p-3.5 rounded-xl bg-emerald-50/70 hover:bg-emerald-100/80 border border-emerald-200 text-left transition-all group"
            >
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-emerald-800 flex items-center space-x-1.5">
                  <Shield className="w-4 h-4 text-emerald-600" />
                  <span>Clean Corporate Email</span>
                </span>
                <Play className="w-3.5 h-3.5 text-emerald-600 opacity-0 group-hover:opacity-100 transition-opacity" />
              </div>
              <p className="text-[11px] text-slate-500 mt-1">Valid internal sprint retro meeting minutes</p>
            </button>
          </div>
        </div>

        {/* Mailbox Watch Form */}
        <div className="pt-4 border-t border-slate-200 space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-slate-700 uppercase tracking-wider">
              Monitor Mailboxes (Google Workspace / Gmail Push Sync)
            </span>
            <button
              type="button"
              onClick={() => setShowAdvancedGcp(!showAdvancedGcp)}
              className="text-xs font-semibold text-red-600 hover:text-red-700 transition-colors"
            >
              {showAdvancedGcp ? '− Hide GCP Topic' : '+ Custom GCP Pub/Sub Topic'}
            </button>
          </div>

          {watchNotification && (
            <div
              className={`p-3 rounded-lg text-xs flex items-center justify-between transition-all ${
                watchNotification.type === 'success'
                  ? 'bg-emerald-50 text-emerald-800 border border-emerald-200'
                  : 'bg-red-50 text-red-800 border border-red-200'
              }`}
            >
              <span>{watchNotification.message}</span>
              <button
                onClick={() => setWatchNotification(null)}
                className="text-slate-400 hover:text-slate-700 ml-2 text-sm leading-none"
              >
                ✕
              </button>
            </div>
          )}

          <form onSubmit={handleRegisterWatch} className="space-y-2">
            <div className="flex flex-col sm:flex-row gap-2">
              <input
                type="email"
                placeholder="Enter mailbox to watch (e.g. security-team@company.com)..."
                value={watchEmail}
                onChange={(e) => setWatchEmail(e.target.value)}
                className="flex-1 bg-white border border-slate-200 rounded-lg px-3.5 py-2.5 text-sm text-slate-900 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-red-500/20 focus:border-red-500"
                required
              />
              <button
                type="submit"
                disabled={watchLoading}
                className="btn-primary whitespace-nowrap text-sm px-5 py-2.5"
              >
                {watchLoading ? 'Registering...' : '+ Register Mailbox Watch'}
              </button>
            </div>

            {showAdvancedGcp && (
              <div className="pt-1">
                <input
                  type="text"
                  placeholder="projects/{project_id}/topics/{topic_name} (leave empty to use default/demo)"
                  value={customTopic}
                  onChange={(e) => setCustomTopic(e.target.value)}
                  className="w-full bg-white border border-slate-200 rounded-lg px-3.5 py-2 text-xs font-mono text-slate-800 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-red-500/20 focus:border-red-500"
                />
                <p className="text-[11px] text-slate-500 mt-1">
                  Optional: Specify custom Google Cloud Pub/Sub topic. Defaults to <code className="text-red-600 font-semibold">projects/tracex-demo/topics/gmail-inbox-watch</code>.
                </p>
              </div>
            )}
          </form>

          {/* Demo / Live Status Note */}
          <div className="flex items-center space-x-2 text-[11px] text-slate-600 bg-slate-50 p-3 rounded-lg border border-slate-200">
            <span className="w-2 h-2 rounded-full bg-sky-500 animate-pulse flex-shrink-0" />
            <span>
              <strong>Zero GCP Setup Required:</strong> In Demo mode, inboxes register instantly as active simulated monitors. Connect GCP Service Accounts in <code className="text-slate-800">backend/.env</code> for live enterprise Gmail push syncing.
            </span>
          </div>

          {/* Watched Mailboxes list */}
          {watchStatus?.watch_manager?.mailboxes && Object.keys(watchStatus.watch_manager.mailboxes).length > 0 && (
            <div className="mt-3 space-y-1.5">
              <p className="text-xs text-slate-700 font-bold">Active Watched Mailboxes (7-day renewal cycle):</p>
              <div className="divide-y divide-slate-100 bg-white rounded-lg border border-slate-200">
                {Object.entries(watchStatus.watch_manager.mailboxes).map(([email, info]: [string, any]) => {
                  const isSim = info.is_simulated || info.status?.includes('demo')
                  return (
                    <div key={email} className="p-3 flex items-center justify-between text-xs">
                      <div className="flex items-center space-x-2">
                        <span className="font-semibold text-slate-800">{email}</span>
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-semibold border ${
                            isSim
                              ? 'bg-sky-50 text-sky-700 border-sky-200'
                              : 'bg-emerald-50 text-emerald-700 border-emerald-200'
                          }`}
                        >
                          {isSim ? 'Demo Watch' : 'GCP Pub/Sub'}
                        </span>
                        <span className="text-slate-500 truncate max-w-xs hidden sm:inline">
                          Topic: {info.topic_name || 'projects/tracex-demo/topics/gmail-inbox-watch'}
                        </span>
                        {info.expiration && (
                          <span className="text-emerald-700 font-medium hidden md:inline">
                            Expires: {new Date(info.expiration).toLocaleDateString()}
                          </span>
                        )}
                      </div>
                      <button
                        onClick={() => handleStopWatch(email)}
                        className="text-red-600 hover:text-red-700 font-semibold ml-2"
                      >
                        Stop Watch
                      </button>
                    </div>
                  )
                })}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Live Ingestion Stream */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="text-xl font-bold flex items-center space-x-2 text-slate-900">
            <span>Inbound Threat Analysis Stream</span>
            {events.length > 0 && (
              <span className="px-2.5 py-0.5 rounded-full bg-red-50 text-xs font-bold text-red-700 border border-red-200">
                {events.length} active
              </span>
            )}
          </h2>

          {events.length > 0 && (
            <button
              onClick={() => setEvents([])}
              className="text-xs text-slate-500 hover:text-red-600 font-semibold flex items-center space-x-1 transition-colors"
            >
              <Trash2 className="w-3.5 h-3.5" />
              <span>Clear Feed</span>
            </button>
          )}
        </div>

        {events.length === 0 ? (
          <div className="card-elevated bg-white p-12 text-center space-y-4">
            <Radio className="w-12 h-12 text-slate-400 mx-auto animate-pulse" />
            <div className="max-w-md mx-auto">
              <h3 className="text-base font-bold text-slate-900">Awaiting Real-Time Threat Events...</h3>
              <p className="text-xs text-slate-500 mt-1 leading-relaxed">
                The WebSocket listener is active. Incoming push notifications from Google Cloud Pub/Sub or manual simulations will stream live threat verdicts into this feed instantly.
              </p>
              <div className="mt-5">
                <button
                  onClick={() => runSimulation('phishing')}
                  className="btn-primary text-xs px-4 py-2.5 inline-flex items-center space-x-2"
                >
                  <Play className="w-3.5 h-3.5" />
                  <span>Test Feed with Simulated Threat</span>
                </button>
              </div>
            </div>
          </div>
        ) : (
          <div className="space-y-3">
            {events.map((evt) => {
              const data = evt.data || {}
              const riskScore = data.risk_score || 0
              const severity = data.severity || 'INFO'
              const isCritical = riskScore >= 70 || data.is_malicious
              const isSuspicious = riskScore >= 40 || data.is_suspicious

              return (
                <div
                  key={evt.id}
                  className={`card bg-white p-5 border-l-4 transition-all duration-300 hover:shadow-md ${
                    isCritical
                      ? 'border-l-red-600 border-slate-200'
                      : isSuspicious
                      ? 'border-l-amber-500 border-slate-200'
                      : 'border-l-emerald-500 border-slate-200'
                  }`}
                >
                  <div className="flex flex-col md:flex-row md:items-start justify-between gap-3">
                    <div className="space-y-2 flex-1 min-w-0">
                      <div className="flex items-center space-x-2 flex-wrap gap-y-1">
                        <span
                          className={`px-2.5 py-0.5 rounded-md text-[10px] font-bold uppercase tracking-wider ${
                            isCritical
                              ? 'bg-red-600 text-white shadow-xs'
                              : isSuspicious
                              ? 'bg-amber-500 text-white shadow-xs'
                              : 'bg-emerald-600 text-white shadow-xs'
                          }`}
                        >
                          {severity} ({riskScore}/100)
                        </span>

                        {data.threat_type && (
                          <span className="px-2 py-0.5 rounded bg-slate-100 text-slate-700 border border-slate-200 text-[10px] font-semibold uppercase">
                            {data.threat_type}
                          </span>
                        )}

                        <span className="text-[11px] text-slate-500">
                          Source: <span className="text-slate-700 font-mono font-medium">{evt.source}</span>
                        </span>

                        <span className="text-[11px] text-slate-400">
                          {new Date(evt.timestamp).toLocaleTimeString()}
                        </span>
                      </div>

                      <h3 className="text-base font-bold text-slate-900 truncate">
                        {data.subject || 'Threat Event Broadcast'}
                      </h3>

                      <div className="flex items-center space-x-4 text-xs text-slate-500">
                        <span>From: <strong className="text-slate-800">{data.from_address || 'Unknown'}</strong></span>
                        {data.to_addresses && data.to_addresses.length > 0 && (
                          <span>To: <strong className="text-slate-800">{data.to_addresses[0]}</strong></span>
                        )}
                      </div>

                      {/* Authentication Status Pills */}
                      {data.authentication && (
                        <div className="flex items-center space-x-2 pt-1">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-semibold border ${
                              data.authentication.spf?.status === 'PASS'
                                ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                                : 'bg-red-50 text-red-700 border-red-200'
                            }`}
                          >
                            SPF: {data.authentication.spf?.status || 'UNKNOWN'}
                          </span>
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-semibold border ${
                              data.authentication.dkim?.status === 'PASS'
                                ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                                : 'bg-red-50 text-red-700 border-red-200'
                            }`}
                          >
                            DKIM: {data.authentication.dkim?.status || 'UNKNOWN'}
                          </span>
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-semibold border ${
                              data.authentication.dmarc?.status === 'PASS'
                                ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                                : 'bg-red-50 text-red-700 border-red-200'
                            }`}
                          >
                            DMARC: {data.authentication.dmarc?.status || 'UNKNOWN'}
                          </span>
                        </div>
                      )}
                    </div>

                    {/* Right Action Button */}
                    {data.email_id && (
                      <div className="flex md:flex-col items-end justify-between gap-2">
                        <Link
                          to={`/emails/${data.email_id}`}
                          className="inline-flex items-center space-x-1.5 px-3.5 py-1.5 rounded-lg bg-red-600 hover:bg-red-700 text-white text-xs font-semibold shadow-xs transition-colors"
                        >
                          <span>Forensic Dossier</span>
                          <ArrowRight className="w-3.5 h-3.5" />
                        </Link>
                      </div>
                    )}
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </div>
    </div>
  )
}
