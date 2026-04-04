export type EvidenceType =
  | 'disk_image'
  | 'filesystem'
  | 'log_file'
  | 'browser_data'
  | 'windows_artifact'
  | 'prefetch'
  | 'jump_list'
  | 'shellbag'
  | 'recent_files'
  | 'apk'
  | 'image'
  | 'document'
  | 'network_capture'
  | 'memory_dump'
  | 'registry_hive';

export type EvidenceStatus = 'pending' | 'processing' | 'analyzed' | 'error';

export type SeverityLevel = 'benign' | 'suspicious' | 'highly_suspicious' | 'critical';

export type ActionCategory =
  | 'file_opened'
  | 'file_created'
  | 'file_modified'
  | 'file_deleted'
  | 'file_copied'
  | 'file_downloaded'
  | 'file_executed'
  | 'file_hidden'
  | 'program_run'
  | 'browser_opened'
  | 'web_page_visited'
  | 'search_query'
  | 'network_connection'
  | 'data_exfiltration'
  | 'login_attempt'
  | 'registry_change'
  | 'service_start'
  | 'process_created'
  | 'driver_loaded'
  | 'usb_connected'
  | 'system_shutdown'
  | 'unknown';

export interface Evidence {
  id: string;
  caseId: string;
  name: string;
  type: EvidenceType;
  path: string;
  size: number;
  hash: string;
  status: EvidenceStatus;
  uploadedAt: string;
  analyzedAt?: string;
  metadata?: Record<string, unknown>;
}

export interface CaseInfo {
  id: string;
  name: string;
  description: string;
  createdAt: string;
  status: 'active' | 'closed' | 'archived';
  evidenceIds: string[];
  analyst: string;
}

export interface TimelineEvent {
  id: string;
  timestamp: string;
  action: ActionCategory;
  entity: string;
  description: string;
  source: string;
  confidence: number;
  severity: SeverityLevel;
  metadata?: Record<string, unknown>;
  relatedEvents?: string[];
}

export interface RewindEvent {
  id: string;
  timestamp: string;
  action: ActionCategory;
  entity: string;
  user?: string;
  process?: string;
  description: string;
  source: string;
  confidence: number;
  icon?: string;
  color?: string;
}

export interface CorrelationNode {
  id: string;
  type: 'file' | 'process' | 'user' | 'ip' | 'domain' | 'url' | 'hash' | 'registry' | 'artifact';
  label: string;
  properties: Record<string, unknown>;
  severity?: SeverityLevel;
}

export interface CorrelationEdge {
  source: string;
  target: string;
  relation: string;
  weight: number;
  timestamp?: string;
}

export interface CorrelationGraph {
  nodes: CorrelationNode[];
  edges: CorrelationEdge[];
}

export interface SuspiciousFinding {
  id: string;
  severity: SeverityLevel;
  category: string;
  title: string;
  description: string;
  evidence: string;
  timestamp: string;
  relatedArtifacts: string[];
  confidence: number;
  recommendation: string;
}

export interface KeywordResult {
  keyword: string;
  matches: {
    file: string;
    line: number;
    context: string;
    source: string;
  }[];
  totalMatches: number;
}

export interface GeoIPResult {
  ip: string;
  country: string;
  city: string;
  latitude: number;
  longitude: number;
  isp: string;
  timestamp: string;
}

export interface ActivityHeatmap {
  hour: number;
  day: number;
  count: number;
}

export interface CustodyEntry {
  id: string;
  evidenceId: string;
  action: string;
  performedBy: string;
  timestamp: string;
  details: string;
  hash?: string;
}

export interface ForensicReport {
  caseInfo: CaseInfo;
  evidenceSummary: Evidence[];
  timeline: TimelineEvent[];
  keyFindings: SuspiciousFinding[];
  rewindSequence: RewindEvent[];
  correlations: CorrelationGraph;
  heatmap: ActivityHeatmap[];
  keywordResults: KeywordResult[];
  geoIPResults: GeoIPResult[];
  chainOfCustody: CustodyEntry[];
  conclusion: string;
  generatedAt: string;
}

export interface IOCItem {
  type: 'ip' | 'domain' | 'url' | 'email' | 'hash' | 'mac' | 'bitcoin' | 'cve' | 'file_path';
  value: string;
  source: string; // which evidence file it came from
  context: string; // surrounding text/sentence
  severity: 'critical' | 'high' | 'medium' | 'low';
  firstSeen: string; // timestamp when found
  tags: string[];
}

export interface EvidenceTag {
  id: string;
  evidenceId: string;
  label: string;
  color: string;
  createdAt: string;
}

export interface CaseData {
  id: string;
  name: string;
  description: string;
  status: 'active' | 'closed' | 'archived';
  createdAt: string;
  updatedAt: string;
  analyst: string;
  tags: string[];
  notes: string[];
}

export interface AnalysisResult {
  caseId: string;
  caseInfo: CaseInfo;
  evidence: Evidence[];
  custody: CustodyEntry[];
  timeline: TimelineEvent[];
  rewindSequence: RewindEvent[];
  suspiciousFindings: SuspiciousFinding[];
  correlations: CorrelationGraph;
  heatmap: ActivityHeatmap[];
  keywordResults: KeywordResult[];
  geoIPResults: GeoIPResult[];
  iocs: IOCItem[];
  stats: {
    totalEvents: number;
    suspiciousCount: number;
    criticalCount: number;
    timeRange: { start: string; end: string };
    topCategories: { category: string; count: number }[];
  };
}
