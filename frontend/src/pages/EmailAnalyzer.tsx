import { useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import { analyzeRawEmail, uploadEmailFile } from '../services/api'
import {
  Upload, FileText, AlertTriangle, CheckCircle, ShieldAlert,
  MapPin, Globe, Cpu, Hash, ArrowRight, CornerDownRight, ExternalLink
} from 'lucide-react'
import type { EmailAnalysisResponse } from '../types'

const SAMPLES = {
  phishing: `Delivered-To: victim@corporation.com
Received: from mail.suspicious-relay.org (mail.suspicious-relay.org [185.220.101.5])
        by mx.google.com with ESMTPS id xyz123;
        Wed, 18 Sep 2024 10:21:02 -0700
Received-SPF: fail (google.com: domain of support@paypa1-security.com does not designate 185.220.101.5 as permitted sender) client-ip=185.220.101.5;
Authentication-Results: mx.google.com;
       dkim=fail header.i=@paypal.com;
       spf=fail smtp.mailfrom=support@paypa1-security.com;
       dmarc=fail (p=REJECT) header.from=paypal.com
Message-ID: <unusual-id-998273612@suspicious-relay.org>
Date: Wed, 18 Sep 2024 17:21:00 +0000
From: "PayPal Security Center" <service@paypal.com>
Reply-To: "Account Verification Desk" <verify@paypa1-security.com>
To: <victim@corporation.com>
Subject: URGENT: Your PayPal Account Has Been Suspended - Action Required

Dear Customer,

We detected unusual activity on your PayPal account. Your account access has been temporarily suspended.
You must confirm your identity within 24 hours:

http://185.220.101.5/login-verification?token=9283748293

Thank you,
PayPal Security Team`,

  ceo_spoof: `Delivered-To: cfo@corporation.com
Received: from unknown-host.dynamic.isp.com (unknown [192.168.1.45])
        by mx.google.com with SMTP id spoof789;
        Mon, 16 Sep 2024 09:32:12 -0500
Received-SPF: fail (google.com: domain of ceo@corporation-secure.com does not designate 192.168.1.45 as permitted sender);
Authentication-Results: mx.google.com;
       dkim=none;
       spf=fail smtp.mailfrom=ceo@corporation-secure.com;
       dmarc=fail header.from=corporation.com
From: "Robert Williams - CEO" <ceo@corporation.com>
Reply-To: <robert.w.temp@freemail-service.com>
To: <cfo@corporation.com>
Subject: URGENT: Confidential Wire Transfer - Time Sensitive Acquisition

Sarah,

I need you to execute a confidential wire transfer of $475,000 USD before 3 PM today.
Beneficiary: HK Strategic Acquisitions Ltd
Account: 8834-9921-4455-2211

Confirm directly to my personal email: robert.w.temp@freemail-service.com

Robert Williams
CEO, Corporation Inc.`,

  clean: `Delivered-To: employee@acme-corp.com
Received: from mail-smtp.acme-corp.com (mail.acme-corp.com [203.0.113.5])
        by mx.google.com with ESMTPS id def456;
        Thu, 19 Sep 2024 08:45:30 -0700
Received-SPF: pass client-ip=203.0.113.5;
Authentication-Results: mx.google.com;
       dkim=pass header.i=@acme-corp.com;
       spf=pass smtp.mailfrom=ceo@acme-corp.com;
       dmarc=pass header.from=acme-corp.com
DKIM-Signature: v=1; a=rsa-sha256; d=acme-corp.com; s=default;
From: "John Smith - CEO" <ceo@acme-corp.com>
To: <employee@acme-corp.com>
Subject: Q3 Project Update and Team Meeting Schedule

Hi Team,

I've scheduled a project review meeting for next Tuesday at 2 PM in Conference Room B.
Please review the slide deck before the meeting.

Best regards,
John Smith
CEO, ACME Corporation`
}

export default function EmailAnalyzer() {
  const [activeTab, setActiveTab] = useState<'paste' | 'upload'>('paste')
  const [rawText, setRawText] = useState('')
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const [result, setResult] = useState<EmailAnalysisResponse | null>(null)

  const analyzeMutation = useMutation({
    mutationFn: (content: string) => analyzeRawEmail(content),
    onSuccess: (data) => setResult(data),
  })

  const uploadMutation = useMutation({
    mutationFn: (file: File) => uploadEmailFile(file),
    onSuccess: (data) => setResult(data),
  })

  const isLoading = analyzeMutation.isPending || uploadMutation.isPending

  const handleAnalyze = () => {
    if (activeTab === 'paste' && rawText.trim()) {
      analyzeMutation.mutate(rawText)
    } else if (activeTab === 'upload' && selectedFile) {
      uploadMutation.mutate(selectedFile)
    }
  }

  const loadSample = (type: keyof typeof SAMPLES) => {
    setActiveTab('paste')
    setRawText(SAMPLES[type])
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-black tracking-tight text-slate-900 mb-2">Email Threat & Forensic Analyzer</h1>
        <p className="text-slate-500 text-sm">
          Upload raw RFC 822 email files or paste headers for deep forensic decomposition, AI analysis, and threat intelligence.
        </p>
      </div>

      {/* Input Card */}
      <div className="card bg-white">
        {/* Sample Loaders */}
        <div className="flex flex-wrap items-center justify-between gap-4 pb-4 mb-4 border-b border-slate-200">
          <span className="text-xs font-bold text-slate-700 uppercase tracking-wider">Quick Test Scenarios:</span>
          <div className="flex flex-wrap gap-2">
            <button
              onClick={() => loadSample('phishing')}
              className="px-3 py-1.5 bg-red-50 text-red-700 border border-red-200 rounded-lg text-xs font-semibold hover:bg-red-100 transition-colors"
            >
              Phishing & Spoofing
            </button>
            <button
              onClick={() => loadSample('ceo_spoof')}
              className="px-3 py-1.5 bg-amber-50 text-amber-800 border border-amber-200 rounded-lg text-xs font-semibold hover:bg-amber-100 transition-colors"
            >
              BEC Wire Transfer
            </button>
            <button
              onClick={() => loadSample('clean')}
              className="px-3 py-1.5 bg-emerald-50 text-emerald-800 border border-emerald-200 rounded-lg text-xs font-semibold hover:bg-emerald-100 transition-colors"
            >
              Clean Corporate Email
            </button>
          </div>
        </div>

        {/* Tab Selection */}
        <div className="flex space-x-4 mb-4">
          <button
            onClick={() => setActiveTab('paste')}
            className={`flex items-center space-x-2 px-4 py-2 border-b-2 font-semibold text-sm transition-colors ${
              activeTab === 'paste'
                ? 'border-red-600 text-red-600'
                : 'border-transparent text-slate-500 hover:text-slate-800'
            }`}
          >
            <FileText className="w-4 h-4" />
            <span>Paste Raw Email (.eml / RFC 822)</span>
          </button>
          <button
            onClick={() => setActiveTab('upload')}
            className={`flex items-center space-x-2 px-4 py-2 border-b-2 font-semibold text-sm transition-colors ${
              activeTab === 'upload'
                ? 'border-red-600 text-red-600'
                : 'border-transparent text-slate-500 hover:text-slate-800'
            }`}
          >
            <Upload className="w-4 h-4" />
            <span>Upload .EML File</span>
          </button>
        </div>

        {/* Tab Body */}
        {activeTab === 'paste' ? (
          <textarea
            value={rawText}
            onChange={(e) => setRawText(e.target.value)}
            placeholder="Paste full raw email with headers here (Received, From, Subject, SPF/DKIM)..."
            className="w-full px-3.5 py-2.5 bg-white border border-slate-200 rounded-lg text-slate-900 placeholder-slate-400 font-mono text-xs h-64 focus:outline-none focus:ring-2 focus:ring-red-500/20 focus:border-red-500"
          />
        ) : (
          <div className="border-2 border-dashed border-slate-300 rounded-xl p-12 text-center bg-slate-50/50">
            <Upload className="w-12 h-12 text-slate-400 mx-auto mb-4" />
            <input
              type="file"
              accept=".eml,.msg,.txt"
              onChange={(e) => setSelectedFile(e.target.files?.[0] || null)}
              className="block w-full text-sm text-slate-600 file:mr-4 file:py-2.5 file:px-4 file:rounded-lg file:border-0 file:text-sm file:font-semibold file:bg-red-600 file:text-white hover:file:bg-red-700 cursor-pointer"
            />
            <p className="text-xs text-slate-400 mt-2">Supported formats: .eml, .msg, .txt (Max 25MB)</p>
          </div>
        )}

        <div className="mt-4 flex justify-end">
          <button
            onClick={handleAnalyze}
            disabled={isLoading || (activeTab === 'paste' ? !rawText.trim() : !selectedFile)}
            className="btn-primary bg-red-600 hover:bg-red-700 text-white flex items-center space-x-2"
          >
            {isLoading ? (
              <>
                <div className="animate-spin rounded-full h-4 w-4 border-2 border-white border-t-transparent"></div>
                <span>Deconstructing & Analyzing...</span>
              </>
            ) : (
              <>
                <ShieldAlert className="w-4 h-4" />
                <span>Execute Deep Forensic Analysis</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Analysis Results Display */}
      {result && (
        <div className="space-y-6">
          {/* Top Verdict Banner */}
          <div className={`card ${result.is_malicious ? 'bg-red-50/70 border-red-200/90' : result.is_suspicious ? 'bg-amber-50/70 border-amber-200/90' : 'bg-emerald-50/70 border-emerald-200/90'}`}>
            <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
              <div className="flex items-center space-x-4">
                <div className={`p-4 rounded-xl shadow-xs ${result.is_malicious ? 'bg-red-600 text-white' : result.is_suspicious ? 'bg-amber-600 text-white' : 'bg-emerald-600 text-white'}`}>
                  {result.is_malicious ? <ShieldAlert className="w-8 h-8" /> : <CheckCircle className="w-8 h-8" />}
                </div>
                <div>
                  <div className="flex items-center space-x-3">
                    <h2 className="text-2xl font-black tracking-tight text-slate-900">
                      {result.is_malicious ? 'THREAT DETECTED: MALICIOUS EMAIL' : result.is_suspicious ? 'SUSPICIOUS EMAIL FLAGGED' : 'CLEAN EMAIL VERIFIED'}
                    </h2>
                    <span className="badge badge-critical font-mono font-bold">{result.severity}</span>
                  </div>
                  <p className="text-sm text-slate-600 mt-1 font-medium">
                    Threat Classification: <span className="font-bold uppercase text-red-600">{result.threat_type || 'Benign Communication'}</span>
                  </p>
                </div>
              </div>

              {/* Risk Score Circle */}
              <div className="bg-white border border-slate-200 shadow-xs px-6 py-4 rounded-xl text-center">
                <p className="text-xs text-slate-500 font-bold uppercase tracking-wider">Explainable Risk Score</p>
                <p className="text-3xl font-black font-mono text-red-600 mt-1">
                  {result.risk_score.toFixed(0)} <span className="text-sm text-slate-400 font-normal">/ 100</span>
                </p>
              </div>
            </div>
          </div>

          {/* Grid: Authentication & Risk Breakdown */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Authentication Protocols */}
            <div className="card bg-white">
              <h3 className="text-lg font-bold text-slate-900 mb-4 flex items-center space-x-2">
                <ShieldAlert className="w-5 h-5 text-red-600" />
                <span>Authentication Protocol Forensics</span>
              </h3>

              <div className="grid grid-cols-3 gap-3 mb-4">
                <div className="bg-slate-50 p-3 rounded-lg border border-slate-200">
                  <div className="flex justify-between items-center mb-1">
                    <span className="text-xs font-bold text-slate-800">SPF</span>
                    <span className={`badge ${result.authentication.spf.status === 'PASS' ? 'badge-success' : 'badge-critical'}`}>
                      {result.authentication.spf.status}
                    </span>
                  </div>
                  <p className="text-xs text-slate-500 truncate">{result.authentication.spf.details || 'No record'}</p>
                </div>

                <div className="bg-slate-50 p-3 rounded-lg border border-slate-200">
                  <div className="flex justify-between items-center mb-1">
                    <span className="text-xs font-bold text-slate-800">DKIM</span>
                    <span className={`badge ${result.authentication.dkim.status === 'PASS' ? 'badge-success' : 'badge-critical'}`}>
                      {result.authentication.dkim.status}
                    </span>
                  </div>
                  <p className="text-xs text-slate-500 truncate">{result.authentication.dkim.details || 'No signature'}</p>
                </div>

                <div className="bg-slate-50 p-3 rounded-lg border border-slate-200">
                  <div className="flex justify-between items-center mb-1">
                    <span className="text-xs font-bold text-slate-800">DMARC</span>
                    <span className={`badge ${result.authentication.dmarc.status === 'PASS' ? 'badge-success' : 'badge-critical'}`}>
                      {result.authentication.dmarc.status}
                    </span>
                  </div>
                  <p className="text-xs text-slate-500 truncate">{result.authentication.dmarc.details || 'No policy'}</p>
                </div>
              </div>

              <div className="bg-slate-50 p-3.5 rounded-lg text-xs text-slate-700 border border-slate-200 leading-relaxed">
                <p className="font-bold text-slate-900 mb-1">Forensic Implication:</p>
                <p>{result.authentication.spf.explanation}</p>
              </div>
            </div>

            {/* Explainable Risk Factors */}
            <div className="card bg-white">
              <h3 className="text-lg font-bold text-slate-900 mb-4 flex items-center space-x-2">
                <Hash className="w-5 h-5 text-red-600" />
                <span>Explainable Risk Factor Calculation</span>
              </h3>

              <div className="space-y-2 max-h-56 overflow-y-auto pr-1">
                {result.risk_breakdown.factors.map((factor, idx) => (
                  <div key={idx} className="flex items-center justify-between p-2.5 rounded-lg bg-slate-50 border border-slate-200 text-xs">
                    <div className="flex items-center space-x-2">
                      <span className="badge badge-high font-bold">+{factor.points}</span>
                      <span className="text-slate-800 font-medium">{factor.description}</span>
                    </div>
                    <span className="text-slate-500 font-mono text-[10px] font-semibold">{factor.category}</span>
                  </div>
                ))}
                {result.risk_breakdown.factors.length === 0 && (
                  <p className="text-xs text-slate-400 italic">No adverse risk points accrued.</p>
                )}
              </div>
            </div>
          </div>

          {/* AI Forensic Reasoning & Recommendation */}
          {result.ai_analysis && (
            <div className="card bg-red-50/20 border-red-200">
              <h3 className="text-lg font-bold mb-3 flex items-center space-x-2 text-red-700">
                <Cpu className="w-5 h-5" />
                <span>AI Forensic Threat Analysis & Reasoning</span>
                {result.ai_analysis.is_fallback && (
                  <span className="badge badge-info ml-2">Rule-Based Reasoning Engine</span>
                )}
              </h3>

              <p className="text-sm text-slate-800 leading-relaxed bg-white p-4 rounded-xl border border-slate-200 mb-4 shadow-xs">
                {result.ai_analysis.reasoning}
              </p>

              {result.ai_analysis.recommended_actions.length > 0 && (
                <div>
                  <h4 className="text-xs font-bold uppercase text-slate-600 mb-2">SOC Recommended Remediation Actions:</h4>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                    {result.ai_analysis.recommended_actions.map((act, idx) => (
                      <div key={idx} className="flex items-start space-x-2 text-xs text-slate-700 bg-white p-3 rounded-lg border border-slate-200 shadow-xs">
                        <CornerDownRight className="w-4 h-4 text-red-600 flex-shrink-0 mt-0.5" />
                        <span>{act}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Email Route / Mail Path Visualizer */}
          <div className="card bg-white">
            <h3 className="text-lg font-bold text-slate-900 mb-4 flex items-center space-x-2">
              <Globe className="w-5 h-5 text-red-600" />
              <span>Email Route & Relay Hop Forensic Path</span>
            </h3>

            <div className="space-y-3">
              {result.header_analysis.received_chain.map((hop, idx) => (
                <div key={idx} className="flex items-center space-x-4 bg-slate-50 p-3.5 rounded-xl border border-slate-200">
                  <div className="w-8 h-8 rounded-full bg-red-600 text-white flex items-center justify-center font-bold text-xs shadow-xs">
                    {hop.hop_number}
                  </div>
                  <div className="flex-1 grid grid-cols-1 md:grid-cols-3 gap-2 text-xs">
                    <div>
                      <span className="text-slate-500">Origin IP:</span>{' '}
                      <span className="font-mono text-red-600 font-bold">{hop.from_ip || 'Hidden / Direct'}</span>
                    </div>
                    <div>
                      <span className="text-slate-500">From Host:</span>{' '}
                      <span className="font-mono text-slate-700 truncate">{hop.from_hostname || 'N/A'}</span>
                    </div>
                    <div>
                      <span className="text-slate-500">Receiving MTA:</span>{' '}
                      <span className="font-mono text-slate-700 truncate">{hop.by_hostname || 'N/A'}</span>
                    </div>
                  </div>
                </div>
              ))}
              {result.header_analysis.received_chain.length === 0 && (
                <p className="text-xs text-slate-400">No Received headers available in this message.</p>
              )}
            </div>
          </div>

          {/* IP Geolocation Context Card */}
          {result.ip_intelligence.length > 0 && (
            <div className="card bg-white">
              <h3 className="text-lg font-bold text-slate-900 mb-4 flex items-center space-x-2">
                <MapPin className="w-5 h-5 text-red-600" />
                <span>Originating Sender IP Geolocation & ASN Intelligence</span>
              </h3>

              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                {result.ip_intelligence.map((ip, idx) => (
                  <div key={idx} className="bg-slate-50 p-4 rounded-xl border border-slate-200">
                    <p className="font-mono text-sm font-bold text-red-600 mb-2">{ip.ip_address}</p>
                    <div className="space-y-1.5 text-xs text-slate-700">
                      <p><span className="text-slate-500">Country:</span> {ip.country || 'Unknown'} ({ip.country_code})</p>
                      <p><span className="text-slate-500">ISP / Owner:</span> {ip.isp || 'N/A'}</p>
                      <p><span className="text-slate-500">ASN:</span> {ip.asn || 'N/A'}</p>
                      <p><span className="text-slate-500">Reputation Score:</span> <strong className="text-red-600">{ip.reputation_score || 0}</strong>/100</p>
                    </div>
                    <div className="mt-3 pt-2 border-t border-slate-200 text-[10px] text-slate-500">
                      {ip.context_note}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
