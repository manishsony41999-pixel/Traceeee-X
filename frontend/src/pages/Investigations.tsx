import { useQuery } from '@tanstack/react-query'
import { listCases } from '../services/api'
import { FileText, Clock, AlertTriangle, User, ChevronRight } from 'lucide-react'
import type { CaseSummary } from '../types'

function getSeverityColor(severity: string) {
  switch (severity.toLowerCase()) {
    case 'critical': return 'badge-critical'
    case 'high': return 'badge-high'
    case 'medium': return 'badge-medium'
    case 'low': return 'badge-low'
    default: return 'badge-info'
  }
}

function getStatusColor(status: string) {
  switch (status) {
    case 'open': return 'text-blue-700 bg-blue-50 border-blue-200'
    case 'under_investigation': return 'text-amber-800 bg-amber-50 border-amber-200'
    case 'contained': return 'text-orange-700 bg-orange-50 border-orange-200'
    case 'closed': return 'text-slate-700 bg-slate-100 border-slate-200'
    default: return 'text-slate-700 bg-slate-100 border-slate-200'
  }
}

export default function Investigations() {
  const { data: cases, isLoading } = useQuery({
    queryKey: ['cases'],
    queryFn: () => listCases(0, 100),
  })

  // Demo cases for display
  const demoCases: CaseSummary[] = [
    {
      id: 1,
      case_id: 'CASE-20240918-A1B2',
      title: 'PayPal Phishing Campaign Investigation',
      description: 'Credential harvesting campaign targeting corporate email accounts',
      status: 'under_investigation',
      severity: 'high',
      analyst_name: 'Security Analyst',
      emails_count: 3,
      evidence_count: 8,
      alerts_count: 2,
      created_at: new Date(Date.now() - 86400000 * 2).toISOString(),
      updated_at: new Date(Date.now() - 3600000).toISOString(),
    },
    {
      id: 2,
      case_id: 'CASE-20240916-C3D4',
      title: 'CEO Wire Transfer BEC Attack',
      description: 'Business Email Compromise spoofing executive identity',
      status: 'contained',
      severity: 'critical',
      analyst_name: 'Senior Analyst',
      emails_count: 1,
      evidence_count: 5,
      alerts_count: 1,
      created_at: new Date(Date.now() - 86400000 * 4).toISOString(),
      updated_at: new Date(Date.now() - 7200000).toISOString(),
    },
    {
      id: 3,
      case_id: 'CASE-20240915-E5F6',
      title: 'Invoice Malware Distribution',
      description: 'Macro-enabled spreadsheet delivering ransomware payload',
      status: 'closed',
      severity: 'high',
      analyst_name: 'SOC Team',
      emails_count: 2,
      evidence_count: 6,
      alerts_count: 3,
      created_at: new Date(Date.now() - 86400000 * 5).toISOString(),
      updated_at: new Date(Date.now() - 86400000 * 1).toISOString(),
    }
  ]

  const displayCases = cases && cases.length > 0 ? cases : demoCases

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="text-center">
          <div className="inline-block animate-spin rounded-full h-12 w-12 border-b-2 border-red-600"></div>
          <p className="mt-4 text-slate-500 font-medium">Loading investigations...</p>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-black tracking-tight text-slate-900 mb-1">Investigation Case Management</h1>
          <p className="text-slate-500 text-sm">Active forensic investigations and security incident case tracking</p>
        </div>
        <button className="btn-primary bg-red-600 hover:bg-red-700 text-white shadow-xs">
          Create New Case
        </button>
      </div>

      {/* Cases List */}
      <div className="space-y-4">
        {displayCases.map((caseItem) => (
          <div key={caseItem.id} className="card bg-white hover:border-red-300 hover:shadow-md transition-all cursor-pointer">
            <div className="flex items-start justify-between gap-4">
              <div className="flex-1">
                <div className="flex items-center space-x-2.5 mb-2.5">
                  <span className="badge badge-info font-mono text-xs">{caseItem.case_id}</span>
                  <span className={`badge ${getSeverityColor(caseItem.severity)} uppercase font-bold`}>
                    {caseItem.severity}
                  </span>
                  <span className={`badge ${getStatusColor(caseItem.status)} font-semibold`}>
                    {caseItem.status.replace('_', ' ').toUpperCase()}
                  </span>
                </div>

                <h3 className="text-lg font-bold text-slate-900 mb-1.5">{caseItem.title}</h3>
                <p className="text-sm text-slate-600 mb-4 leading-relaxed">{caseItem.description}</p>

                <div className="flex flex-wrap items-center gap-5 text-xs text-slate-500 font-medium">
                  <div className="flex items-center space-x-1.5">
                    <FileText className="w-4 h-4 text-slate-400" />
                    <span>{caseItem.emails_count} Email{caseItem.emails_count !== 1 ? 's' : ''}</span>
                  </div>
                  <div className="flex items-center space-x-1.5">
                    <AlertTriangle className="w-4 h-4 text-amber-500" />
                    <span>{caseItem.alerts_count} Alert{caseItem.alerts_count !== 1 ? 's' : ''}</span>
                  </div>
                  <div className="flex items-center space-x-1.5">
                    <Clock className="w-4 h-4 text-slate-400" />
                    <span>Updated {new Date(caseItem.updated_at).toLocaleDateString()}</span>
                  </div>
                  {caseItem.analyst_name && (
                    <div className="flex items-center space-x-1.5">
                      <User className="w-4 h-4 text-slate-400" />
                      <span>{caseItem.analyst_name}</span>
                    </div>
                  )}
                </div>
              </div>

              <div className="flex items-center space-x-3">
                <div className="text-right">
                  <p className="text-2xl font-black font-mono text-red-600">{caseItem.evidence_count}</p>
                  <p className="text-xs text-slate-400 font-medium">Evidence Items</p>
                </div>
                <ChevronRight className="w-5 h-5 text-slate-400" />
              </div>
            </div>
          </div>
        ))}
      </div>

      {displayCases.length === 0 && (
        <div className="card bg-white text-center py-12">
          <FileText className="w-12 h-12 text-slate-400 mx-auto mb-3" />
          <p className="text-slate-500">No investigation cases found. Create a new case to get started.</p>
        </div>
      )}
    </div>
  )
}
