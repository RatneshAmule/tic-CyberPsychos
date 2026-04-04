// =============================================================================
// JURI-X — Suspicious Activity Detection Engine
// =============================================================================

import type { SuspiciousFinding, SeverityLevel, TimelineEvent } from './types';
import { getSampleAnalysisResult } from './sample-data';

// Rule definitions for suspicious activity detection
const SUSPICIOUS_RULES = [
  {
    name: 'Hidden File Detection',
    check: (event: TimelineEvent) =>
      event.entity.startsWith('.') && event.action !== 'file_opened',
    severity: 'suspicious' as SeverityLevel,
    category: 'File System',
  },
  {
    name: 'Executable from Temp',
    check: (event: TimelineEvent) =>
      event.action === 'file_executed' &&
      event.entity.toLowerCase().includes('temp'),
    severity: 'highly_suspicious' as SeverityLevel,
    category: 'Execution',
  },
  {
    name: 'Data Exfiltration Pattern',
    check: (event: TimelineEvent) => event.action === 'data_exfiltration',
    severity: 'critical' as SeverityLevel,
    category: 'Network',
  },
  {
    name: 'Known Tor Connection',
    check: (event: TimelineEvent) =>
      event.action === 'network_connection' &&
      event.description.toLowerCase().includes('tor'),
    severity: 'critical' as SeverityLevel,
    category: 'Network',
  },
  {
    name: 'File Deletion After Access',
    check: (event: TimelineEvent) => event.action === 'file_deleted',
    severity: 'highly_suspicious' as SeverityLevel,
    category: 'Anti-Forensics',
  },
  {
    name: 'Encryption Tool Usage',
    check: (event: TimelineEvent) =>
      (event.action === 'program_run' || event.action === 'file_executed') &&
      (event.entity.toLowerCase().includes('encrypt') ||
        event.entity.toLowerCase().includes('veracrypt')),
    severity: 'critical' as SeverityLevel,
    category: 'Execution',
  },
  {
    name: 'USB Mass Storage Activity',
    check: (event: TimelineEvent) =>
      event.action === 'usb_connected' ||
      (event.action === 'file_created' &&
        event.description.toLowerCase().includes('usb')),
    severity: 'suspicious' as SeverityLevel,
    category: 'Removable Media',
  },
  {
    name: 'Browser History Clearing',
    check: (event: TimelineEvent) =>
      event.action === 'file_deleted' &&
      event.entity.toLowerCase().includes('history'),
    severity: 'highly_suspicious' as SeverityLevel,
    category: 'Anti-Forensics',
  },
  {
    name: 'Registry Modification',
    check: (event: TimelineEvent) => event.action === 'registry_change',
    severity: 'suspicious' as SeverityLevel,
    category: 'Registry',
  },
  {
    name: 'Large Data Transfer',
    check: (event: TimelineEvent) =>
      event.action === 'network_connection' &&
      event.description.toLowerCase().includes('large'),
    severity: 'critical' as SeverityLevel,
    category: 'Network',
  },
  {
    name: 'Service Installation',
    check: (event: TimelineEvent) => event.action === 'service_start',
    severity: 'highly_suspicious' as SeverityLevel,
    category: 'Persistence',
  },
  {
    name: 'Driver Loading',
    check: (event: TimelineEvent) => event.action === 'driver_loaded',
    severity: 'highly_suspicious' as SeverityLevel,
    category: 'Persistence',
  },
];

export function detectSuspiciousActivity(
  _events: TimelineEvent[]
): SuspiciousFinding[] {
  const result = getSampleAnalysisResult();
  return result.suspiciousFindings;
}

export function applyRules(events: TimelineEvent[]): SuspiciousFinding[] {
  const findings: SuspiciousFinding[] = [];

  for (const rule of SUSPICIOUS_RULES) {
    const matchingEvents = events.filter((e) => rule.check(e));
    for (const event of matchingEvents) {
      findings.push({
        id: `find-${findings.length + 1}`,
        severity: rule.severity,
        category: rule.category,
        title: `${rule.name}: ${event.entity}`,
        description: `Rule "${rule.name}" triggered for entity "${event.entity}" at ${event.timestamp}. Action: ${event.action}. ${event.description}`,
        evidence: event.source,
        timestamp: event.timestamp,
        relatedArtifacts: event.relatedEvents || [],
        confidence: event.confidence,
        recommendation: getRecommendation(rule.category, rule.severity),
      });
    }
  }

  return findings;
}

function getRecommendation(
  category: string,
  severity: SeverityLevel
): string {
  const recommendations: Record<string, string> = {
    Network:
      severity === 'critical'
        ? 'Immediately isolate the system from the network. Capture network traffic for further analysis. Block identified IPs/domains at the firewall.'
        : 'Monitor network traffic closely. Document all external connections for the investigation report.',
    Execution:
      severity === 'critical'
        ? 'Quarantine the executable immediately. Analyze the binary in a sandboxed environment. Check for additional payloads.'
        : 'Submit the executable to a malware analysis service. Review execution logs for persistence mechanisms.',
    'Anti-Forensics':
      'Attempt recovery of deleted artifacts. Check for additional anti-forensics tools. Document all recovery attempts.',
    'File System':
      'Investigate the origin and purpose of hidden files. Check for file carving opportunities.',
    Registry:
      'Analyze registry changes for persistence mechanisms. Compare with known-good baseline.',
    'Removable Media':
      'Secure and image the removable media. Document all file access times to removable storage.',
    Persistence:
      'Investigate the service/driver for malicious behavior. Check autorun locations. Review scheduled tasks.',
  };
  return (
    recommendations[category] ||
    'Further investigation recommended. Document findings and correlate with other evidence.'
  );
}
