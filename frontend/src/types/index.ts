/**
 * TypeScript type definitions for TRACE-X frontend
 */

export type CaseSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type CaseStatus = 'open' | 'under_investigation' | 'contained' | 'closed';
export type AlertSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export type AuthStatus = 'PASS' | 'FAIL' | 'NEUTRAL' | 'NONE' | 'UNKNOWN';

export interface DashboardStats {
  total_emails_analyzed: number;
  threats_detected: number;
  critical_alerts: number;
  high_risk_emails: number;
  suspicious_ips: number;
  suspicious_domains: number;
  malicious_urls: number;
  cases_opened: number;
  active_threats_percent: number;
}

export interface AuthResult {
  status: AuthStatus;
  details: string | null;
  raw_header: string | null;
  explanation: string;
}

export interface EmailAuthenticationAnalysis {
  spf: AuthResult;
  dkim: AuthResult;
  dmarc: AuthResult;
  arc?: AuthResult;
  summary: string;
}

export interface EmailHop {
  hop_number: number;
  from_ip: string | null;
  from_hostname: string | null;
  by_hostname: string | null;
  timestamp: string | null;
  delay_seconds: number | null;
  anomalies: string[];
}

export interface HeaderAnalysisResult {
  originating_ip: string | null;
  received_chain: EmailHop[];
  sender_domain: string | null;
  reply_to_domain: string | null;
  message_id_valid: boolean;
  anomalies: string[];
  timezone_inconsistencies: string[];
}

export interface RiskFactor {
  category: string;
  points: number;
  description: string;
  evidence_ref?: string;
}

export interface RiskScoreBreakdown {
  score: number;
  severity: string;
  factors: RiskFactor[];
  explanation: string;
  confidence: number;
}

export interface AIAnalysisResult {
  classification: string;
  confidence: number;
  severity: string;
  indicators: string[];
  reasoning: string;
  recommended_actions: string[];
  evidence_citations: string[];
  is_fallback: boolean;
}

export interface IPIntelligenceData {
  ip_address: string;
  country: string | null;
  country_code: string | null;
  region: string | null;
  city: string | null;
  latitude: number | null;
  longitude: number | null;
  isp: string | null;
  asn: string | null;
  organization: string | null;
  is_hosting: boolean | null;
  is_proxy: boolean | null;
  is_vpn: boolean | null;
  is_tor: boolean | null;
  reputation_score: number | null;
  is_malicious: boolean;
  abuse_confidence_score: number | null;
  total_reports: number | null;
  provider: string;
  context_note: string;
  is_demo: boolean;
}

export interface DomainIntelligenceData {
  domain: string;
  tld: string | null;
  registrar: string | null;
  creation_date: string | null;
  domain_age_days: number | null;
  is_malicious: boolean;
  is_suspicious: boolean;
  is_lookalike: boolean;
  lookalike_target: string | null;
  has_suspicious_tld: boolean;
  reputation_score: number | null;
  threat_types: string[];
  provider: string;
  is_demo: boolean;
}

export interface URLItem {
  url: string;
  domain: string | null;
  protocol: string | null;
  is_suspicious: boolean;
  is_malicious: boolean;
  is_shortened: boolean;
  is_ip_based: boolean;
  has_suspicious_tld: boolean;
  uses_https: boolean;
  reputation_score: number | null;
  threat_types: string[];
  indicators: string[];
}

export interface AttachmentItem {
  filename: string;
  file_extension: string | null;
  mime_type: string | null;
  file_size: number | null;
  sha256_hash: string | null;
  md5_hash: string | null;
  is_suspicious: boolean;
  is_malicious: boolean;
  is_executable: boolean;
  has_macros: boolean;
  reputation_score: number | null;
  threat_types: string[];
  indicators: string[];
}

export interface EmailAnalysisResponse {
  email_id: string;
  message_id: string | null;
  subject: string | null;
  from_address: string | null;
  to_addresses: string[];
  cc_addresses: string[] | null;
  reply_to: string | null;
  return_path: string | null;
  date_sent: string | null;
  date_received: string | null;
  is_suspicious: boolean;
  is_malicious: boolean;
  threat_type: string | null;
  risk_score: number;
  severity: string;
  authentication: EmailAuthenticationAnalysis;
  header_analysis: HeaderAnalysisResult;
  risk_breakdown: RiskScoreBreakdown;
  ai_analysis: AIAnalysisResult | null;
  ip_intelligence: IPIntelligenceData[];
  domain_intelligence: DomainIntelligenceData[];
  urls: URLItem[];
  attachments: AttachmentItem[];
  case_id: string | null;
  alert_id: string | null;
  analyzed_at: string;
  is_demo: boolean;
}

export interface EmailListItem {
  id: number;
  email_id: string;
  subject: string | null;
  from_address: string | null;
  to_addresses: string[] | null;
  risk_score: number;
  threat_type: string | null;
  is_malicious: boolean;
  is_suspicious: boolean;
  spf_result: string | null;
  dkim_result: string | null;
  dmarc_result: string | null;
  created_at: string;
}

export interface CaseSummary {
  id: number;
  case_id: string;
  title: string;
  description: string | null;
  status: CaseStatus;
  severity: CaseSeverity;
  analyst_name: string | null;
  emails_count: number;
  evidence_count: number;
  alerts_count: number;
  created_at: string;
  updated_at: string;
}

export interface EvidenceResponse {
  id: number;
  evidence_id: string;
  case_id: number;
  email_id: number | null;
  evidence_type: string;
  title: string;
  description: string | null;
  extracted_value: string | null;
  metadata: Record<string, any> | null;
  source: string | null;
  evidence_hash: string;
  previous_hash: string | null;
  chain_index: number;
  integrity_verified: boolean;
  verified_at: string | null;
  collected_at: string;
}

export interface LedgerVerificationResult {
  case_id: string;
  total_records: number;
  is_valid: boolean;
  compromised_index: number | null;
  message: string;
  timestamp: string;
}
