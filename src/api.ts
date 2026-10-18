export const API_BASE_URL = (import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000').replace(/\/$/, '');

export const API_TIMEOUT_MS = 15_000;

export class ApiError extends Error {
  status: number;
  detail?: unknown;

  constructor(message: string, status: number, detail?: unknown) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.detail = detail;
  }
}

export interface HealthResponse {
  status: string;
  service: string;
  version: string;
  database: string;
  providers?: Record<string, boolean>;
}

export interface IntelligenceFinding {
  source: string;
  status: string;
  verdict: string;
  explanation: string;
  [key: string]: unknown;
}

export interface IntelligenceResult {
  analysis_id?: number;
  indicator_type: string;
  indicator: string;
  classification: string;
  algorithm?: string | null;
  valid: boolean;
  externally_queried: boolean;
  configured_providers?: string[];
  verdict: string;
  checked_at?: string;
  results: IntelligenceFinding[];
  findings?: IntelligenceFinding[];
  source_attribution?: string[];
  explanation: string;
  blocked_reason?: string | null;
}

export interface HashResult {
  analysis_id?: number;
  metadata?: {
    filename?: string;
    content_type?: string;
    mime_type?: string;
    size_bytes?: number;
    extension?: string | null;
    detected_file_type?: string;
  };
  hashes: Record<string, string>;
  source?: string;
  executed?: boolean;
  uploaded_externally?: boolean;
  [key: string]: unknown;
}

export interface IocResult {
  analysis_id?: number;
  input_metadata?: { filename?: string | null; size_bytes?: number };
  urls: string[];
  ipv4: string[];
  ipv6: string[];
  domains: string[];
  emails: string[];
  hashes: Record<string, string[]>;
  cves: string[];
  counts: Record<string, number>;
  observations: Observation[];
}

export interface LogResult {
  analysis_id?: number;
  format: string;
  total_records: number;
  normalized_records: Array<Record<string, unknown>>;
  failed_login_count: number;
  groups: {
    failed_logins_by_source: Record<string, number>;
    failed_logins_by_username: Record<string, number>;
    event_type_source?: Record<string, number>;
  };
  repeated_events?: Array<{ group: string; count: number; rule: string }>;
  unusual_frequency?: Array<{ group: string; count: number; rule: string }>;
  timeline?: Array<Record<string, unknown>>;
  observations: Observation[];
}

export interface Observation {
  source: string;
  explanation: string;
}

export interface EventRecord {
  id: number;
  event_type?: string | null;
  type?: string | null;
  source?: string | null;
  timestamp?: string | null;
  severity?: string | null;
  detail?: string | null;
  payload?: Record<string, unknown>;
  normalized?: Record<string, unknown>;
  case_ids?: number[];
  created_at?: string | null;
}

export interface AssetRecord {
  id: number;
  name: string;
  hostname?: string | null;
  ip?: string | null;
  kind?: string | null;
  risk?: string | null;
  status?: string | null;
  operating_system?: string | null;
  owner?: string | null;
  software?: Array<Record<string, unknown>> | Record<string, unknown> | null;
  last_assessment_date?: string | null;
  notes?: string | null;
  metadata?: Record<string, unknown>;
  case_ids?: number[];
  created_at?: string | null;
  updated_at?: string | null;
}

export interface CaseRecord {
  id: number;
  title: string;
  name?: string;
  description?: string | null;
  status: string;
  priority: string;
  assignee?: string | null;
  metadata?: Record<string, unknown>;
  asset_ids: number[];
  event_ids: number[];
  related_indicators?: string[];
  indicators?: string[];
  vulnerability_ids?: string[];
  analyst_notes?: string | null;
  activities?: Array<{ id: number; action: string; detail: string; actor?: string | null; created_at?: string | null }>;
  created_at?: string | null;
  updated_at?: string | null;
}

export interface ConditionNode {
  op?: 'and' | 'or';
  type?: 'and' | 'or';
  conditions?: ConditionNode[];
  children?: ConditionNode[];
  field?: string;
  operator?: string;
  value?: unknown;
}

export interface RuleRecord {
  id: number;
  name: string;
  description?: string | null;
  enabled: boolean;
  condition: ConditionNode;
  condition_tree?: ConditionNode;
  tags: string[];
  created_at?: string | null;
  updated_at?: string | null;
}

export interface RuleTestMatch {
  event_id: number;
  matched: boolean;
  event_type?: string | null;
  source?: string | null;
  explanation?: string;
}

export interface RuleTestResult {
  rule_id: number;
  enabled: boolean;
  evaluated_count: number;
  matched_count: number;
  matches: RuleTestMatch[];
}

export interface VulnerabilityRecord {
  source: string;
  id: string;
  description?: string | null;
  cvss_score?: number | null;
  severity?: string | null;
  published?: string | null;
  last_modified?: string | null;
  references: string[];
}

export interface VulnerabilitySearchResult {
  source: string;
  page: number;
  limit: number;
  total: number;
  results: VulnerabilityRecord[];
  upstream?: Record<string, unknown>;
}

export interface GraphNode {
  id: string;
  kind: string;
  type: string;
  label: string;
  source: string;
  explanation: string;
  data: Record<string, unknown>;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  relation: string;
  type: string;
  source_attribution: string;
  evidence_source?: string;
  explanation: string;
}

export interface GraphResult {
  nodes: GraphNode[];
  edges: GraphEdge[];
  source: string;
}

export interface CaseReport {
  case: Record<string, unknown>;
  assets: Array<Record<string, unknown>>;
  events: Array<Record<string, unknown>>;
  analysis_records: Array<Record<string, unknown>>;
  source: string;
  explanation: string;
}

export interface Collection<T> {
  items: T[];
  total: number;
}

export interface EventCollection extends Collection<EventRecord> {
  offset: number;
  limit: number;
}

export interface AssetInput {
  name: string;
  hostname?: string;
  ip?: string;
  kind?: string;
  risk?: string;
  status?: string;
  operating_system?: string;
  owner?: string;
  software?: Array<Record<string, unknown>> | Record<string, unknown>;
  last_assessment_date?: string;
  notes?: string;
  metadata?: Record<string, unknown>;
}

export interface CaseInput {
  title: string;
  description?: string;
  status?: string;
  priority?: string;
  assignee?: string;
  metadata?: Record<string, unknown>;
  asset_ids?: number[];
  event_ids?: number[];
  indicators?: string[];
  vulnerability_ids?: string[];
  analyst_notes?: string;
}

export interface RuleInput {
  name: string;
  description?: string;
  enabled?: boolean;
  condition: ConditionNode;
  tags?: string[];
}

export interface AssetAssessmentResult {
  asset_id: number;
  asset_name: string;
  kind: 'tcp' | 'http';
  target: string;
  status: string;
  authorized: boolean;
  started_at: string;
  analysis_id?: number;
  port?: number;
  http_status?: number;
  headers?: Record<string, string>;
  error?: string;
  elapsed_ms?: number;
}

type JsonBody = object;

async function readResponseBody(response: Response): Promise<unknown> {
  const text = await response.text();
  if (!text) return undefined;
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return text;
  }
}

function errorMessage(payload: unknown, fallback: string): string {
  if (typeof payload === 'string' && payload.trim()) return payload;
  if (payload && typeof payload === 'object') {
    const record = payload as Record<string, unknown>;
    if (typeof record.detail === 'string') return record.detail;
    if (typeof record.error === 'string') return record.error;
    if (Array.isArray(record.details)) {
      const first = record.details[0];
      if (first && typeof first === 'object' && typeof (first as Record<string, unknown>).msg === 'string') {
        return String((first as Record<string, unknown>).msg);
      }
    }
  }
  return fallback;
}

export async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), API_TIMEOUT_MS);
  const headers = new Headers(init.headers);
  if (init.body && !(init.body instanceof FormData) && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }
  if (!headers.has('Accept')) headers.set('Accept', 'application/json');

  try {
    const response = await fetch(`${API_BASE_URL}${path}`, {
      ...init,
      headers,
      signal: controller.signal,
    });
    const payload = await readResponseBody(response);
    if (!response.ok) {
      throw new ApiError(errorMessage(payload, `Request failed with HTTP ${response.status}`), response.status, payload);
    }
    return payload as T;
  } catch (error) {
    if (error instanceof ApiError) throw error;
    if ((error instanceof DOMException && error.name === 'AbortError') || (error instanceof Error && error.name === 'AbortError')) {
      throw new ApiError(`Request timed out after ${API_TIMEOUT_MS / 1000} seconds`, 408);
    }
    if (error instanceof TypeError) {
      throw new ApiError('Backend is unavailable. Check that the BLACKSITE API is running.', 0);
    }
    throw error;
  } finally {
    clearTimeout(timeout);
  }
}

async function requestBlob(path: string): Promise<Blob> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), API_TIMEOUT_MS);
  try {
    const response = await fetch(`${API_BASE_URL}${path}`, {
      headers: { Accept: '*/*' },
      signal: controller.signal,
    });
    if (!response.ok) {
      const payload = await readResponseBody(response);
      throw new ApiError(errorMessage(payload, `Request failed with HTTP ${response.status}`), response.status, payload);
    }
    return await response.blob();
  } catch (error) {
    if (error instanceof ApiError) throw error;
    if ((error instanceof DOMException && error.name === 'AbortError') || (error instanceof Error && error.name === 'AbortError')) {
      throw new ApiError(`Request timed out after ${API_TIMEOUT_MS / 1000} seconds`, 408);
    }
    if (error instanceof TypeError) {
      throw new ApiError('Backend is unavailable. Check that the BLACKSITE API is running.', 0);
    }
    throw error;
  } finally {
    clearTimeout(timeout);
  }
}

const json = (body: JsonBody): RequestInit => ({ method: 'POST', body: JSON.stringify(body) });

export const api = {
  health: () => request<HealthResponse>('/api/health'),

  intelligence: {
    investigate: (kind: 'ip' | 'url' | 'domain' | 'hash', indicator: string) =>
      request<IntelligenceResult>(`/api/intelligence/${kind}`, json({ indicator })),
  },

  forensics: {
    hashFile: (file: File) => {
      const form = new FormData();
      form.append('file', file, file.name);
      return request<HashResult>('/api/forensics/hash', { method: 'POST', body: form });
    },
    extract: (text: string) => request<IocResult>('/api/forensics/extract', json({ text })),
    logs: (content: string, format: 'json' | 'csv') =>
      request<LogResult>('/api/forensics/logs', json({ content, format })),
  },

  events: {
    list: (params: { offset?: number; limit?: number } = {}) => {
      const query = new URLSearchParams({ offset: String(params.offset ?? 0), limit: String(params.limit ?? 500) });
      return request<EventCollection>(`/api/events?${query.toString()}`);
    },
    import: (content: string, format: 'json' | 'csv') =>
      request<{ imported: number; items: EventRecord[] }>('/api/events/import', json({ content, format })),
  },

  vulnerabilities: {
    search: (query: string, limit = 20, filters: { severity?: string; published_after?: string; published_before?: string } = {}) => {
      const params = new URLSearchParams({ limit: String(limit) });
      if (query.trim()) params.set('query', query.trim());
      if (filters.severity) params.set('severity', filters.severity);
      if (filters.published_after) params.set('published_after', filters.published_after);
      if (filters.published_before) params.set('published_before', filters.published_before);
      return request<VulnerabilitySearchResult>(`/api/vulnerabilities/search?${params.toString()}`);
    },
    detail: (cveId: string) => request<VulnerabilityRecord>(`/api/vulnerabilities/${encodeURIComponent(cveId)}`),
  },

  rules: {
    list: () => request<Collection<RuleRecord>>('/api/rules'),
    create: (body: RuleInput) => request<RuleRecord>('/api/rules', { ...json(body), method: 'POST' }),
    update: (id: number, body: Partial<RuleInput>) => request<RuleRecord>(`/api/rules/${id}`, { ...json(body), method: 'PATCH' }),
    remove: (id: number) => request<{ deleted: boolean; id: number }>(`/api/rules/${id}`, { method: 'DELETE' }),
    test: (id: number, eventIds?: number[]) =>
      request<RuleTestResult>(`/api/rules/${id}/test`, json(eventIds ? { event_ids: eventIds } : {})),
  },

  assets: {
    list: () => request<Collection<AssetRecord>>('/api/assets'),
    create: (body: AssetInput) => request<AssetRecord>('/api/assets', { ...json(body), method: 'POST' }),
    update: (id: number, body: Partial<AssetInput>) => request<AssetRecord>(`/api/assets/${id}`, { ...json(body), method: 'PATCH' }),
    remove: (id: number) => request<{ deleted: boolean; id: number }>(`/api/assets/${id}`, { method: 'DELETE' }),
    assess: (id: number, body: { kind: 'tcp' | 'http'; confirm_authorized: boolean; port?: number; timeout_seconds?: number }) =>
      request<AssetAssessmentResult>(`/api/assets/${id}/assess`, { ...json(body), method: 'POST' }),
    import: (content: string, format: 'json' | 'csv') =>
      request<{ imported: number; items: AssetRecord[] }>('/api/assets/import', json({ content, format })),
  },

  cases: {
    list: () => request<Collection<CaseRecord>>('/api/cases'),
    create: (body: CaseInput) => request<CaseRecord>('/api/cases', { ...json(body), method: 'POST' }),
    update: (id: number, body: Partial<CaseInput>) => request<CaseRecord>(`/api/cases/${id}`, { ...json(body), method: 'PATCH' }),
    remove: (id: number) => request<{ deleted: boolean; id: number }>(`/api/cases/${id}`, { method: 'DELETE' }),
    addNote: (id: number, detail: string, actor?: string) => request<{ id: number; action: string; detail: string; actor?: string | null; created_at?: string | null }>(`/api/cases/${id}/notes`, json({ detail, actor })),
  },

  graph: () => request<GraphResult>('/api/graph'),

  reports: {
    json: (caseId: number) => request<CaseReport>(`/api/reports/cases/${caseId}.json`),
    download: (caseId: number, format: 'json' | 'csv' | 'pdf') => requestBlob(`/api/reports/cases/${caseId}.${format}`),
  },
};

export function formatApiError(error: unknown): string {
  if (error instanceof ApiError) return error.message;
  if (error instanceof Error) return error.message;
  return 'The request could not be completed.';
}
