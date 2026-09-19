/**
 * API Service Layer for TRACE-X Frontend
 * Handles all HTTP requests to the backend API
 */
import axios from 'axios';
import type {
  DashboardStats,
  EmailAnalysisResponse,
  EmailListItem,
  CaseSummary,
  EvidenceResponse,
  LedgerVerificationResult,
  IPIntelligenceData,
  DomainIntelligenceData,
} from '../types';

const API_BASE_URL = import.meta.env.VITE_API_URL || '';

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// ==========================================
// Dashboard
// ==========================================
export const getDashboardStats = async (): Promise<DashboardStats> => {
  const response = await api.get('/api/v1/dashboard/stats');
  return response.data;
};

// ==========================================
// Email Analysis
// ==========================================
export const analyzeRawEmail = async (rawContent: string): Promise<EmailAnalysisResponse> => {
  const response = await api.post('/api/v1/emails/analyze', {
    raw_content: rawContent,
    source: 'manual_paste',
  });
  return response.data;
};

export const uploadEmailFile = async (file: File): Promise<EmailAnalysisResponse> => {
  const formData = new FormData();
  formData.append('file', file);

  const response = await api.post('/api/v1/emails/upload', formData, {
    headers: {
      'Content-Type': 'multipart/form-data',
    },
  });
  return response.data;
};

export const listEmails = async (skip: number = 0, limit: number = 50): Promise<EmailListItem[]> => {
  const response = await api.get('/api/v1/emails/', {
    params: { skip, limit },
  });
  return response.data;
};

export const getEmailAnalysis = async (emailId: string): Promise<EmailAnalysisResponse> => {
  const response = await api.get(`/api/v1/emails/${emailId}`);
  return response.data;
};

export const deleteEmail = async (emailId: string): Promise<void> => {
  await api.delete(`/api/v1/emails/${emailId}`);
};

// ==========================================
// Cases
// ==========================================
export const listCases = async (skip: number = 0, limit: number = 50): Promise<CaseSummary[]> => {
  const response = await api.get('/api/v1/cases/', {
    params: { skip, limit },
  });
  return response.data;
};

export const getCase = async (caseId: string) => {
  const response = await api.get(`/api/v1/cases/${caseId}`);
  return response.data;
};

export const createCase = async (data: {
  title: string;
  description?: string;
  severity: string;
}) => {
  const response = await api.post('/api/v1/cases/', data);
  return response.data;
};

// ==========================================
// Evidence
// ==========================================
export const getCaseEvidence = async (caseId: string): Promise<EvidenceResponse[]> => {
  const response = await api.get(`/api/v1/evidence/case/${caseId}`);
  return response.data;
};

export const verifyEvidenceIntegrity = async (caseId: string): Promise<LedgerVerificationResult> => {
  const response = await api.post(`/api/v1/evidence/verify/${caseId}`);
  return response.data;
};

// ==========================================
// Threat Intelligence
// ==========================================
export const getIPIntelligence = async (ipAddress: string): Promise<IPIntelligenceData> => {
  const response = await api.get(`/api/v1/threat-intelligence/ip/${ipAddress}`);
  return response.data;
};

export const getDomainIntelligence = async (domain: string): Promise<DomainIntelligenceData> => {
  const response = await api.get(`/api/v1/threat-intelligence/domain/${domain}`);
  return response.data;
};

export const getURLReputation = async (url: string) => {
  const response = await api.get('/api/v1/threat-intelligence/url', {
    params: { url },
  });
  return response.data;
};

export const getFileHashReputation = async (hash: string) => {
  const response = await api.get(`/api/v1/threat-intelligence/hash/${hash}`);
  return response.data;
};

// ==========================================
// Health Check
// ==========================================
export const healthCheck = async () => {
  const response = await api.get('/health');
  return response.data;
};

// ==========================================
// Google Workspace Real-Time Ingestion & Threat Stream
// ==========================================

export const getThreatStreamWsUrl = (): string => {
  const httpUrl = import.meta.env.VITE_API_URL || 'http://localhost:8000';
  const wsUrl = httpUrl.replace(/^http/, 'ws');
  return `${wsUrl}/api/v1/ws/threat-stream`;
};

export const getThreatStreamStatus = async () => {
  const response = await api.get('/api/v1/ws/threat-stream/status');
  return response.data;
};

export const broadcastTestAlert = async (message: string, severity: string = 'INFO') => {
  const response = await api.post('/api/v1/ws/threat-stream/broadcast-test', {
    message,
    severity,
  });
  return response.data;
};

export const getGoogleIngestionStatus = async () => {
  const response = await api.get('/api/v1/webhook/google-pubsub/status');
  return response.data;
};

export const registerMailboxWatch = async (email: string, topicName?: string) => {
  const response = await api.post('/api/v1/webhook/google-pubsub/watch', {
    email,
    topic_name: topicName || undefined,
  });
  return response.data;
};

export const stopMailboxWatch = async (email: string) => {
  const response = await api.post('/api/v1/webhook/google-pubsub/stop-watch', {
    email,
  });
  return response.data;
};

export const simulateRealtimeIngestion = async (userEmail: string, rawEmail: string) => {
  const response = await api.post('/api/v1/webhook/google-pubsub/simulate', {
    user_email: userEmail,
    raw_email: rawEmail,
    broadcast_websocket: true,
  });
  return response.data;
};

// ==========================================
// AI SOC Analyst Copilot API
// ==========================================

export interface CopilotMessage {
  role: 'user' | 'assistant' | 'system';
  content: string;
}

export interface CopilotQueryRequest {
  messages: CopilotMessage[];
  threat_context?: Record<string, any> | null;
}

export interface CopilotQueryResponse {
  response: string;
  role: string;
  model: string;
  threat_context_applied: boolean;
  suggested_actions?: string[];
}

export const querySocCopilot = async (payload: CopilotQueryRequest): Promise<CopilotQueryResponse> => {
  const response = await api.post('/api/v1/chat/query', payload);
  return response.data;
};

export const getSocCopilotStatus = async () => {
  const response = await api.get('/api/v1/chat/status');
  return response.data;
};

export default api;


