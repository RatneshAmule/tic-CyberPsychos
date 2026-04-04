// =============================================================================
// JURI-X — Forensic Rewind Mode Engine
// =============================================================================

import type { RewindEvent, ActionCategory } from './types';
import { getSampleAnalysisResult } from './sample-data';

export function buildRewindSequence(_events: unknown[]): RewindEvent[] {
  const result = getSampleAnalysisResult();
  return result.rewindSequence;
}

export function getRewindSummary(events: RewindEvent[]): {
  totalDuration: string;
  actionCounts: { action: ActionCategory; count: number }[];
  userActivity: { user: string; actions: number }[];
  riskPhases: { start: string; end: string; risk: string; events: number }[];
} {
  if (events.length === 0) {
    return {
      totalDuration: '0m',
      actionCounts: [],
      userActivity: [],
      riskPhases: [],
    };
  }

  const start = new Date(events[0].timestamp).getTime();
  const end = new Date(events[events.length - 1].timestamp).getTime();
  const durationMs = end - start;
  const hours = Math.floor(durationMs / (1000 * 60 * 60));
  const minutes = Math.floor((durationMs % (1000 * 60 * 60)) / (1000 * 60));
  const totalDuration =
    hours > 0 ? `${hours}h ${minutes}m` : `${minutes}m`;

  // Count actions by category
  const actionMap = new Map<ActionCategory, number>();
  events.forEach((e) => {
    actionMap.set(e.action, (actionMap.get(e.action) || 0) + 1);
  });
  const actionCounts = Array.from(actionMap.entries())
    .map(([action, count]) => ({ action, count }))
    .sort((a, b) => b.count - a.count);

  // User activity
  const userMap = new Map<string, number>();
  events.forEach((e) => {
    const user = e.user || 'unknown';
    userMap.set(user, (userMap.get(user) || 0) + 1);
  });
  const userActivity = Array.from(userMap.entries())
    .map(([user, actions]) => ({ user, actions }))
    .sort((a, b) => b.actions - a.actions);

  // Risk phases (group consecutive high-risk events)
  const highRiskActions: ActionCategory[] = [
    'file_deleted',
    'data_exfiltration',
    'file_executed',
    'network_connection',
    'registry_change',
    'service_start',
    'driver_loaded',
  ];
  const riskPhases: {
    start: string;
    end: string;
    risk: string;
    events: number;
  }[] = [];
  let currentPhase: { start: string; end: string; events: number } | null =
    null;

  for (const event of events) {
    const isHighRisk = highRiskActions.includes(event.action);
    if (isHighRisk) {
      if (!currentPhase) {
        currentPhase = {
          start: event.timestamp,
          end: event.timestamp,
          events: 1,
        };
      } else {
        currentPhase.end = event.timestamp;
        currentPhase.events++;
      }
    } else {
      if (currentPhase && currentPhase.events > 0) {
        riskPhases.push({
          ...currentPhase,
          risk:
            currentPhase.events >= 3
              ? 'critical'
              : currentPhase.events >= 2
                ? 'high'
                : 'medium',
        });
        currentPhase = null;
      }
    }
  }
  if (currentPhase) {
    riskPhases.push({
      ...currentPhase,
      risk:
        currentPhase.events >= 3
          ? 'critical'
          : currentPhase.events >= 2
            ? 'high'
            : 'medium',
    });
  }

  return { totalDuration, actionCounts, userActivity, riskPhases };
}

export function getActionIcon(action: ActionCategory): string {
  const iconMap: Record<ActionCategory, string> = {
    file_opened: 'FileText',
    file_created: 'FilePlus',
    file_modified: 'FileEdit',
    file_deleted: 'Trash2',
    file_copied: 'Copy',
    file_downloaded: 'Download',
    file_executed: 'Play',
    file_hidden: 'EyeOff',
    program_run: 'Terminal',
    browser_opened: 'Globe',
    web_page_visited: 'ExternalLink',
    search_query: 'Search',
    network_connection: 'Wifi',
    data_exfiltration: 'Upload',
    login_attempt: 'LogIn',
    registry_change: 'Settings',
    service_start: 'Cog',
    process_created: 'CPU',
    driver_loaded: 'HardDrive',
    usb_connected: 'Usb',
    system_shutdown: 'Power',
    unknown: 'HelpCircle',
  };
  return iconMap[action] || 'Circle';
}

export function getActionColor(action: ActionCategory): string {
  const colorMap: Record<ActionCategory, string> = {
    file_opened: '#6366f1',
    file_created: '#22c55e',
    file_modified: '#f59e0b',
    file_deleted: '#ef4444',
    file_copied: '#6366f1',
    file_downloaded: '#3b82f6',
    file_executed: '#dc2626',
    file_hidden: '#9333ea',
    program_run: '#f97316',
    browser_opened: '#06b6d4',
    web_page_visited: '#14b8a6',
    search_query: '#8b5cf6',
    network_connection: '#ec4899',
    data_exfiltration: '#dc2626',
    login_attempt: '#0ea5e9',
    registry_change: '#d97706',
    service_start: '#e11d48',
    process_created: '#7c3aed',
    driver_loaded: '#be185d',
    usb_connected: '#059669',
    system_shutdown: '#6b7280',
    unknown: '#9ca3af',
  };
  return colorMap[action] || '#9ca3af';
}
