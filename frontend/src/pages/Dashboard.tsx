import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { getDashboardStats, listEmails } from '../services/api'
import { Activity, AlertTriangle, FileText, Globe, Link as LinkIcon, Mail, Shield, Radio, ArrowRight } from 'lucide-react'
import type { EmailListItem } from '../types'

function StatCard({ icon: Icon, label, value, color }: any) {
  return (
    <div className="card-elevated bg-white">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm text-slate-500 font-medium mb-1">{label}</p>
          <p className="text-3xl font-extrabold text-slate-900">{value.toLocaleString()}</p>
        </div>
        <div className={`p-3 rounded-xl ${color}`}>
          <Icon className="w-6 h-6" />
        </div>
      </div>
    </div>
  )
}

function getSeverityBadge(score: number) {
  if (score >= 80) return 'badge-critical'
  if (score >= 60) return 'badge-high'
  if (score >= 40) return 'badge-medium'
  if (score >= 20) return 'badge-low'
  return 'badge-info'
}

function getSeverityText(score: number) {
  if (score >= 80) return 'CRITICAL'
  if (score >= 60) return 'HIGH'
  if (score >= 40) return 'MEDIUM'
  if (score >= 20) return 'LOW'
  return 'INFO'
}

export default function Dashboard() {
  const { data: stats, isLoading: statsLoading } = useQuery({
    queryKey: ['dashboard-stats'],
    queryFn: getDashboardStats,
    refetchInterval: 30000, // Refresh every 30 seconds
  })

  const { data: recentEmails } = useQuery({
    queryKey: ['recent-emails'],
    queryFn: () => listEmails(0, 10),
    refetchInterval: 30000,
  })

  if (statsLoading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="text-center">
          <div className="inline-block animate-spin rounded-full h-12 w-12 border-b-2 border-red-600"></div>
          <p className="mt-4 text-slate-500 font-medium">Loading dashboard telemetry...</p>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <h1 className="text-3xl font-black tracking-tight text-slate-900 mb-1">
            Security Operations Dashboard
          </h1>
          <p className="text-slate-500 text-sm">Real-time email threat monitoring, forensic telemetry, and incident response analytics</p>
        </div>

        {/* Real-Time Stream Quick Access */}
        <Link
          to="/stream"
          className="inline-flex items-center space-x-3 px-4 py-2.5 rounded-xl bg-red-50 hover:bg-red-100/80 border border-red-200 text-red-700 text-sm font-semibold transition-all shadow-xs group"
        >
          <span className="w-2.5 h-2.5 rounded-full bg-red-600 animate-ping" />
          <Radio className="w-4 h-4 text-red-600" />
          <span>Open Real-Time Threat Stream</span>
          <ArrowRight className="w-4 h-4 text-red-600 group-hover:translate-x-1 transition-transform" />
        </Link>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <StatCard
          icon={Mail}
          label="Total Emails Analyzed"
          value={stats?.total_emails_analyzed || 0}
          color="bg-slate-100 text-slate-700 border border-slate-200"
        />
        <StatCard
          icon={AlertTriangle}
          label="Threats Detected"
          value={stats?.threats_detected || 0}
          color="bg-red-50 text-red-600 border border-red-200"
        />
        <StatCard
          icon={Shield}
          label="Critical Alerts"
          value={stats?.critical_alerts || 0}
          color="bg-red-100 text-red-700 border border-red-200"
        />
        <StatCard
          icon={FileText}
          label="Cases Opened"
          value={stats?.cases_opened || 0}
          color="bg-red-50 text-red-600 border border-red-200"
        />
      </div>

      {/* Secondary Stats */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <StatCard
          icon={Mail}
          label="High Risk Emails"
          value={stats?.high_risk_emails || 0}
          color="bg-amber-50 text-amber-600 border border-amber-200"
        />
        <StatCard
          icon={Globe}
          label="Suspicious IPs"
          value={stats?.suspicious_ips || 0}
          color="bg-slate-100 text-slate-700 border border-slate-200"
        />
        <StatCard
          icon={Activity}
          label="Suspicious Domains"
          value={stats?.suspicious_domains || 0}
          color="bg-slate-100 text-slate-700 border border-slate-200"
        />
        <StatCard
          icon={LinkIcon}
          label="Malicious URLs"
          value={stats?.malicious_urls || 0}
          color="bg-red-50 text-red-600 border border-red-200"
        />
      </div>

      {/* Recent Emails */}
      <div className="card bg-white">
        <div className="flex items-center justify-between mb-6 pb-4 border-b border-slate-200">
          <div>
            <h2 className="text-lg font-bold text-slate-900">Recent Email Ingestion & Analysis</h2>
            <p className="text-xs text-slate-500">Live inspection records and cryptographic risk evaluations</p>
          </div>
          <Link to="/analyze" className="text-sm font-semibold text-red-600 hover:text-red-700 transition-colors">
            Analyze New Email →
          </Link>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-slate-200 text-left text-xs font-bold uppercase tracking-wider text-slate-500">
                <th className="pb-3">From</th>
                <th className="pb-3">Subject</th>
                <th className="pb-3">Risk Score</th>
                <th className="pb-3">Threat Type</th>
                <th className="pb-3">Auth Status</th>
                <th className="pb-3">Analyzed</th>
              </tr>
            </thead>
            <tbody className="text-sm divide-y divide-slate-100">
              {recentEmails?.map((email: EmailListItem) => (
                <tr key={email.id} className="hover:bg-slate-50/80 transition-colors">
                  <td className="py-3.5 pr-3">
                    <div className="font-mono text-xs text-slate-800 font-medium truncate max-w-[200px]">
                      {email.from_address || 'Unknown'}
                    </div>
                  </td>
                  <td className="py-3.5 pr-3 max-w-xs truncate text-slate-900 font-medium">
                    {email.subject || '(No Subject)'}
                  </td>
                  <td className="py-3.5 pr-3">
                    <div className="flex items-center space-x-2">
                      <span className={`badge ${getSeverityBadge(email.risk_score)}`}>
                        {getSeverityText(email.risk_score)}
                      </span>
                      <span className="text-xs font-mono font-bold text-slate-700">{email.risk_score.toFixed(0)}</span>
                    </div>
                  </td>
                  <td className="py-3.5 pr-3">
                    {email.threat_type ? (
                      <span className="badge badge-high">{email.threat_type}</span>
                    ) : (
                      <span className="text-slate-400 font-mono text-xs">—</span>
                    )}
                  </td>
                  <td className="py-3.5 pr-3">
                    <div className="flex items-center space-x-1.5 text-xs font-bold font-mono">
                      <span className={email.spf_result === 'PASS' ? 'text-emerald-600' : 'text-red-600'}>
                        SPF
                      </span>
                      <span className="text-slate-300">/</span>
                      <span className={email.dkim_result === 'PASS' ? 'text-emerald-600' : 'text-red-600'}>
                        DKIM
                      </span>
                      <span className="text-slate-300">/</span>
                      <span className={email.dmarc_result === 'PASS' ? 'text-emerald-600' : 'text-red-600'}>
                        DMARC
                      </span>
                    </div>
                  </td>
                  <td className="py-3.5 text-xs text-slate-500 font-medium">
                    {new Date(email.created_at).toLocaleString()}
                  </td>
                </tr>
              ))}
              {(!recentEmails || recentEmails.length === 0) && (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-slate-400">
                    No emails analyzed yet. Upload an email or start the real-time stream to inspect threats.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Active Threats Indicator */}
      {stats && stats.active_threats_percent > 0 && (
        <div className="card bg-red-50/70 border border-red-200/80">
          <div className="flex items-center space-x-3">
            <div className="p-2 rounded-lg bg-red-100 text-red-600">
              <AlertTriangle className="w-6 h-6" />
            </div>
            <div>
              <h3 className="font-bold text-red-900">Active Threat Activity Detected</h3>
              <p className="text-sm text-red-700 mt-0.5">
                {stats.active_threats_percent}% of analyzed emails contain confirmed threat indicators. Review high-risk cases immediately.
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
