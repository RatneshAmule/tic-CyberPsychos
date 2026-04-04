// =============================================================================
// JURI-X — Report Generation
// =============================================================================

import type { ForensicReport } from './types';
import { getSampleReport } from './sample-data';

export { getSampleReport };

export function generateReport(): ForensicReport {
  return getSampleReport();
}

export function generateReportText(report: ForensicReport): string {
  const lines: string[] = [];

  lines.push(
    '═══════════════════════════════════════════════════════════'
  );
  lines.push('  JURI-X FORENSIC INVESTIGATION REPORT');
  lines.push(
    '═══════════════════════════════════════════════════════════'
  );
  lines.push('');
  lines.push(`Case: ${report.caseInfo.name}`);
  lines.push(`Case ID: ${report.caseInfo.id}`);
  lines.push(`Analyst: ${report.caseInfo.analyst}`);
  lines.push(`Generated: ${report.generatedAt}`);
  lines.push('');

  lines.push('─── EXECUTIVE SUMMARY ───');
  lines.push(report.conclusion);
  lines.push('');

  lines.push('─── EVIDENCE SUMMARY ───');
  lines.push(`Total evidence items: ${report.evidenceSummary.length}`);
  report.evidenceSummary.forEach((e) => {
    lines.push(`  - ${e.name} (${e.type}) - ${e.status}`);
  });
  lines.push('');

  lines.push('─── TIMELINE ───');
  lines.push(`Total events: ${report.timeline.length}`);
  report.timeline.slice(0, 20).forEach((e) => {
    lines.push(
      `  [${e.timestamp}] ${e.action}: ${e.entity} - ${e.severity}`
    );
  });
  if (report.timeline.length > 20) {
    lines.push(
      `  ... and ${report.timeline.length - 20} more events`
    );
  }
  lines.push('');

  lines.push('─── KEY FINDINGS ───');
  report.keyFindings.forEach((f) => {
    lines.push(`  [${f.severity.toUpperCase()}] ${f.title}`);
    lines.push(`    ${f.description}`);
    lines.push(`    Recommendation: ${f.recommendation}`);
    lines.push('');
  });
  lines.push('');

  lines.push('─── REWIND SEQUENCE ───');
  report.rewindSequence.forEach((e) => {
    lines.push(`  [${e.timestamp}] → ${e.action}: ${e.entity}`);
  });
  lines.push('');

  lines.push('─── CHAIN OF CUSTODY ───');
  report.chainOfCustody.forEach((c) => {
    lines.push(
      `  [${c.timestamp}] ${c.action} by ${c.performedBy}: ${c.details}`
    );
  });
  lines.push('');

  lines.push(
    '═══════════════════════════════════════════════════════════'
  );
  lines.push('  END OF REPORT');
  lines.push(
    '═══════════════════════════════════════════════════════════'
  );

  return lines.join('\n');
}
