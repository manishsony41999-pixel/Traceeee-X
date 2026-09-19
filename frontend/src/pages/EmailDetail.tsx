import { useParams } from 'react-router-dom'
import { ShieldAlert } from 'lucide-react'

export default function EmailDetail() {
  const { emailId } = useParams()

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-black tracking-tight text-slate-900 mb-1">Email Investigation Detail</h1>
        <p className="text-slate-500 text-sm">Detailed forensic analysis view for email ID: {emailId}</p>
      </div>

      <div className="card bg-white">
        <div className="flex items-center justify-center py-16">
          <div className="text-center">
            <div className="w-20 h-20 rounded-2xl bg-red-50 border border-red-200 text-red-600 flex items-center justify-center mx-auto mb-4 shadow-xs">
              <ShieldAlert className="w-10 h-10" />
            </div>
            <h3 className="text-xl font-bold text-slate-900 mb-2">Email Detail & Forensics View</h3>
            <p className="text-sm text-slate-500 max-w-md mx-auto leading-relaxed">
              This view displays the complete forensic decomposition for the selected message, including
              RFC headers, cryptographic authentication results, reputation telemetry, and MITRE ATT&CK mapping.
            </p>
            <div className="mt-5">
              <span className="inline-flex items-center px-3 py-1 rounded-full bg-red-50 text-red-700 border border-red-200 font-mono text-xs font-bold">
                Email Record ID: {emailId}
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
