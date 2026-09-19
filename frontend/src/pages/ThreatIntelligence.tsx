import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { getIPIntelligence, getDomainIntelligence, getURLReputation, getFileHashReputation } from '../services/api'
import { Search } from 'lucide-react'

type QueryType = 'ip' | 'domain' | 'url' | 'hash'

export default function ThreatIntelligence() {
  const [queryType, setQueryType] = useState<QueryType>('ip')
  const [queryInput, setQueryInput] = useState('185.220.101.5')
  const [activeQuery, setActiveQuery] = useState<{ type: QueryType; value: string } | null>({
    type: 'ip',
    value: '185.220.101.5'
  })

  const { data: result, isLoading } = useQuery({
    queryKey: ['threat-intel', activeQuery?.type, activeQuery?.value],
    queryFn: async () => {
      if (!activeQuery || !activeQuery.value) return null
      if (activeQuery.type === 'ip') return await getIPIntelligence(activeQuery.value)
      if (activeQuery.type === 'domain') return await getDomainIntelligence(activeQuery.value)
      if (activeQuery.type === 'url') return await getURLReputation(activeQuery.value)
      if (activeQuery.type === 'hash') return await getFileHashReputation(activeQuery.value)
      return null
    },
    enabled: Boolean(activeQuery && activeQuery.value),
  })

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault()
    if (queryInput.trim()) {
      setActiveQuery({ type: queryType, value: queryInput.trim() })
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-black tracking-tight text-slate-900 mb-1">Threat Intelligence Engine</h1>
        <p className="text-slate-500 text-sm">
          Query real-time infrastructure reputation, IP geolocation, domain WHOIS, URL analysis, and file signatures.
        </p>
      </div>

      {/* Query Bar */}
      <div className="card bg-white">
        <form onSubmit={handleSearch} className="space-y-4">
          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              onClick={() => { setQueryType('ip'); setQueryInput('185.220.101.5'); }}
              className={`px-4 py-2 rounded-lg text-sm font-semibold transition-all ${queryType === 'ip' ? 'bg-red-600 text-white shadow-xs' : 'bg-slate-100 text-slate-700 hover:bg-slate-200'}`}
            >
              IP Address
            </button>
            <button
              type="button"
              onClick={() => { setQueryType('domain'); setQueryInput('paypa1-security.com'); }}
              className={`px-4 py-2 rounded-lg text-sm font-semibold transition-all ${queryType === 'domain' ? 'bg-red-600 text-white shadow-xs' : 'bg-slate-100 text-slate-700 hover:bg-slate-200'}`}
            >
              Domain / Lookalike
            </button>
            <button
              type="button"
              onClick={() => { setQueryType('url'); setQueryInput('http://185.220.101.5/login-verification'); }}
              className={`px-4 py-2 rounded-lg text-sm font-semibold transition-all ${queryType === 'url' ? 'bg-red-600 text-white shadow-xs' : 'bg-slate-100 text-slate-700 hover:bg-slate-200'}`}
            >
              Suspicious URL
            </button>
            <button
              type="button"
              onClick={() => { setQueryType('hash'); setQueryInput('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'); }}
              className={`px-4 py-2 rounded-lg text-sm font-semibold transition-all ${queryType === 'hash' ? 'bg-red-600 text-white shadow-xs' : 'bg-slate-100 text-slate-700 hover:bg-slate-200'}`}
            >
              File Hash (SHA-256)
            </button>
          </div>

          <div className="flex gap-3">
            <input
              type="text"
              value={queryInput}
              onChange={(e) => setQueryInput(e.target.value)}
              placeholder={`Enter ${queryType.toUpperCase()} to scan...`}
              className="input flex-1 font-mono text-sm"
            />
            <button type="submit" className="btn-primary bg-red-600 hover:bg-red-700 text-white flex items-center space-x-2">
              <Search className="w-4 h-4" />
              <span>Query Intelligence</span>
            </button>
          </div>
        </form>
      </div>

      {/* Loading */}
      {isLoading && (
        <div className="card bg-white text-center py-12">
          <div className="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-red-600"></div>
          <p className="mt-3 text-sm text-slate-500">Querying threat intelligence feeds & geolocation databases...</p>
        </div>
      )}

      {/* Result View */}
      {result && !isLoading && (
        <div className="card bg-white space-y-6">
          <div className="flex items-center justify-between border-b border-slate-200 pb-4">
            <div>
              <span className="badge badge-info uppercase font-mono text-xs font-bold">{activeQuery?.type} Intelligence</span>
              <h2 className="text-xl font-bold font-mono text-red-600 mt-1">{activeQuery?.value}</h2>
            </div>

            <div className="text-right">
              <span className={`badge ${result.is_malicious ? 'badge-critical' : 'badge-success'}`}>
                {result.is_malicious ? 'THREAT FLAGGED' : 'LOW RISK'}
              </span>
              <p className="text-xs text-slate-500 mt-1">Provider: {result.provider || 'TRACE-X Aggregator'}</p>
            </div>
          </div>

          {/* Details Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 text-sm">
            {result.country && (
              <div className="bg-slate-50 p-3.5 rounded-xl border border-slate-200">
                <span className="text-slate-500 text-xs block font-medium">Country / Region</span>
                <span className="font-bold text-slate-900">{result.country} ({result.country_code || 'N/A'})</span>
              </div>
            )}

            {result.isp && (
              <div className="bg-slate-50 p-3.5 rounded-xl border border-slate-200">
                <span className="text-slate-500 text-xs block font-medium">ISP / Autonomous System</span>
                <span className="font-bold text-slate-900">{result.isp} {result.asn ? `(${result.asn})` : ''}</span>
              </div>
            )}

            {result.reputation_score !== undefined && (
              <div className="bg-slate-50 p-3.5 rounded-xl border border-slate-200">
                <span className="text-slate-500 text-xs block font-medium">Reputation Score</span>
                <span className="font-mono font-black text-red-600">{result.reputation_score} / 100</span>
              </div>
            )}

            {result.abuse_confidence_score !== undefined && (
              <div className="bg-slate-50 p-3.5 rounded-xl border border-slate-200">
                <span className="text-slate-500 text-xs block font-medium">Abuse Confidence</span>
                <span className="font-mono font-black text-red-600">{result.abuse_confidence_score}%</span>
              </div>
            )}

            {result.is_lookalike !== undefined && (
              <div className="bg-slate-50 p-3.5 rounded-xl border border-slate-200">
                <span className="text-slate-500 text-xs block font-medium">Lookalike Domain Analysis</span>
                <span className={result.is_lookalike ? 'text-red-600 font-bold' : 'text-slate-700 font-medium'}>
                  {result.is_lookalike ? `Targeting ${result.lookalike_target}` : 'No obvious typosquatting'}
                </span>
              </div>
            )}
          </div>

          {/* Context Note */}
          <div className="bg-slate-50 p-4 rounded-xl border border-slate-200 text-xs text-slate-600 leading-relaxed">
            <p className="font-bold text-slate-800 mb-1">Forensic Note:</p>
            <p>{result.context_note || 'Geolocation and threat intelligence are contextual indicators and do not establish physical attribution.'}</p>
          </div>
        </div>
      )}
    </div>
  )
}
