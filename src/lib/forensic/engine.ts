// =============================================================================
// JURI-X — Forensic Engine Orchestrator
// =============================================================================

import type {
  Evidence,
  AnalysisResult,
  TimelineEvent,
  SuspiciousFinding,
} from './types';
import { getSampleAnalysisResult } from './sample-data';

export class ForensicEngine {
  private caseId: string;
  private events: TimelineEvent[] = [];

  constructor(caseId: string) {
    this.caseId = caseId;
  }

  async analyzeEvidence(evidenceList: Evidence[]): Promise<AnalysisResult> {
    // For demo, use sample data. In production, this would call real forensic tools.
    void evidenceList;
    return getSampleAnalysisResult();
  }

  getStats(result: AnalysisResult) {
    return result.stats;
  }

  getCriticalFindings(result: AnalysisResult): SuspiciousFinding[] {
    return result.suspiciousFindings.filter(
      (f) => f.severity === 'critical' || f.severity === 'highly_suspicious'
    );
  }
}

export const engine = new ForensicEngine('demo-case-001');
