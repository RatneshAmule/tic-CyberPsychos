/**
 * tool-evtx.ts — Windows Event Log (EVTX) Analysis
 *
 * Uses: Hayabusa for comprehensive Windows Event Log analysis with
 * sigma-based detection rules, or falls back to manual parsing
 * using `strings` and pattern matching.
 *
 * Analyzes: Security event logs for login events, process creation,
 * service installation, scheduled tasks, audit log clearing, and more.
 *
 * Detects: brute force attacks, new service installations, audit log
 * tampering, suspicious process execution, and persistence mechanisms.
 *
 * Falls back gracefully if Hayabusa is not installed.
 */

import { execSync } from 'child_process';
import { existsSync, statSync, mkdirSync, readFileSync } from 'fs';
import { basename } from 'path';

// ─── Types ───────────────────────────────────────────────────────────────────

export interface EVTXEvent {
  eventId: number;
  timestamp: string;
  level: string;
  description: string;
  data: Record<string, string>;
}

export interface EVTXDetection {
  rule: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  category: string;
  description: string;
  events: EVTXEvent[];
}

export interface EVTXSuspiciousFinding {
  category: string;
  severity: 'benign' | 'suspicious' | 'highly_suspicious' | 'critical';
  title: string;
  description: string;
  evidence: string;
}

export interface EVTXResult {
  available: boolean;
  filePath: string;
  totalEvents: number;
  criticalEvents: EVTXEvent[];
  suspiciousEvents: EVTXEvent[];
  detections: EVTXDetection[];
  suspiciousFindings: EVTXSuspiciousFinding[];
  toolUsed: string;
  errors: string[];
}

// ─── Constants ───────────────────────────────────────────────────────────────

const HAYABUSA_OUTPUT = '/tmp/juri-x/hayabusa-results.json';
const HAYABUSA_RULES_DIR = '/tmp/juri-x/hayabusa-rules';

/** Windows Security Event IDs of interest with their descriptions. */
const SECURITY_EVENT_IDS: Record<number, { description: string; level: string }> = {
  4624: { description: 'An account was successfully logged on', level: 'info' },
  4625: { description: 'An account failed to log on', level: 'warning' },
  4634: { description: 'An account was logged off', level: 'info' },
  4648: { description: 'A logon was attempted using explicit credentials', level: 'info' },
  4656: { description: 'A handle to an object was requested', level: 'info' },
  4658: { description: 'The handle to an object was closed', level: 'info' },
  4660: { description: 'An object was deleted', level: 'info' },
  4662: { description: 'An operation was performed on an object', level: 'info' },
  4663: { description: 'An attempt was made to access an object', level: 'info' },
  4670: { description: 'Permissions on an object were changed', level: 'warning' },
  4672: { description: 'Special privileges assigned to new logon', level: 'warning' },
  4673: { description: 'A privileged service was called', level: 'warning' },
  4674: { description: 'An operation was attempted on a privileged object', level: 'warning' },
  4688: { description: 'A new process has been created', level: 'info' },
  4689: { description: 'A process has exited', level: 'info' },
  4697: { description: 'A service was installed in the system', level: 'critical' },
  4698: { description: 'A scheduled task was created', level: 'warning' },
  4699: { description: 'A scheduled task was deleted', level: 'warning' },
  4700: { description: 'A scheduled task was enabled', level: 'warning' },
  4701: { description: 'A scheduled task was disabled', level: 'info' },
  4702: { description: 'A scheduled task was updated', level: 'warning' },
  4704: { description: 'A user right was adjusted', level: 'warning' },
  4705: { description: 'A user right was removed', level: 'warning' },
  4712: { description: 'Kerberos authentication ticket was requested', level: 'info' },
  4713: { description: 'Kerberos service ticket was requested', level: 'info' },
  4716: { description: 'Trusted domain information was modified', level: 'critical' },
  4719: { description: 'Audit policy was changed', level: 'critical' },
  4720: { description: 'A user account was created', level: 'warning' },
  4722: { description: 'A user account was enabled', level: 'warning' },
  4723: { description: 'An attempt was made to change an account password', level: 'warning' },
  4724: { description: 'An attempt was made to reset an accounts password', level: 'critical' },
  4725: { description: 'A user account was disabled', level: 'warning' },
  4726: { description: 'A user account was deleted', level: 'critical' },
  4728: { description: 'A member was added to a security-enabled global group', level: 'warning' },
  4732: { description: 'A member was added to a security-enabled local group', level: 'warning' },
  4738: { description: 'A user account was changed', level: 'warning' },
  4740: { description: 'A user account was locked out', level: 'warning' },
  4741: { description: 'A computer account was created', level: 'warning' },
  4742: { description: 'A computer account was changed', level: 'info' },
  4756: { description: 'A member was added to a universal group', level: 'warning' },
  4767: { description: 'A user account was unlocked', level: 'info' },
  4768: { description: 'A Kerberos authentication ticket (TGT) was requested', level: 'info' },
  4769: { description: 'A Kerberos service ticket was requested', level: 'info' },
  4771: { description: 'Kerberos pre-authentication failed', level: 'warning' },
  4776: { description: 'The domain controller attempted to validate credentials', level: 'info' },
  4781: { description: 'The name of an account was changed', level: 'warning' },
  4798: { description: "A user's local group membership was enumerated", level: 'info' },
  4799: { description: 'A security-enabled local group membership was enumerated', level: 'info' },
  4800: { description: 'The workstation was unlocked', level: 'info' },
  4801: { description: 'The workstation was locked', level: 'info' },
  4802: { description: 'The screen saver was invoked', level: 'info' },
  4803: { description: 'The screen saver was dismissed', level: 'info' },
  4946: { description: 'A change has been made to Windows Firewall exception list', level: 'warning' },
  4950: { description: 'A Windows Firewall setting was changed', level: 'warning' },
  4952: { description: 'Windows Firewall rule was modified', level: 'warning' },
  4956: { description: 'Windows Firewall rule was deleted', level: 'warning' },
  4964: { description: 'Special groups have been assigned to a new logon', level: 'warning' },
  4985: { description: 'The state of a transaction has changed', level: 'info' },
  5024: { description: 'The Windows Firewall service has started successfully', level: 'info' },
  5025: { description: 'The Windows Firewall service has been stopped', level: 'critical' },
  5031: { description: 'The Windows Firewall service blocked an application', level: 'warning' },
  5120: { description: 'Cluster resource type was created', level: 'info' },
  1102: { description: 'The audit log was cleared', level: 'critical' },
  1107: { description: 'Audit log full', level: 'warning' },
  7036: { description: 'The service entered the running state', level: 'info' },
  7040: { description: 'The service start type changed', level: 'warning' },
  7045: { description: 'A new service was installed', level: 'critical' },
};

// ─── Helpers ─────────────────────────────────────────────────────────────────

const EXEC_OPTIONS = {
  encoding: 'utf-8' as const,
  maxBuffer: 50 * 1024 * 1024,
  timeout: 120_000,
};

function runTool(cmd: string): string | null {
  try {
    const out = execSync(cmd, EXEC_OPTIONS);
    return (out as string).trim();
  } catch (err: any) {
    const msg = err?.message || String(err);
    if (msg.includes('ENOENT') || msg.includes('not found') || msg.includes('command not found')) {
      console.warn(`[JURI-X EVTX] Tool not found: ${cmd.split(' ')[0]}`);
    } else {
      console.warn(`[JURI-X EVTX] ${cmd.split(' ')[0]} failed: ${msg.substring(0, 200)}`);
    }
    return null;
  }
}

/** Check if Hayabusa is installed. */
function isHayabusaAvailable(): boolean {
  const output = runTool('hayabusa --version 2>/dev/null');
  return output !== null;
}

/** Ensure output directories exist. */
function ensureHayabusaDirs(): boolean {
  try {
    const outputDir = HAYABUSA_OUTPUT.substring(0, HAYABUSA_OUTPUT.lastIndexOf('/'));
    if (!existsSync(outputDir)) {
      mkdirSync(outputDir, { recursive: true });
    }
    if (!existsSync(HAYABUSA_RULES_DIR)) {
      mkdirSync(HAYABUSA_RULES_DIR, { recursive: true });
    }
    return true;
  } catch (err: any) {
    console.warn(`[JURI-X EVTX] Failed to create directories: ${err?.message}`);
    return false;
  }
}

// ─── Hayabusa Analysis ──────────────────────────────────────────────────────

/** Run Hayabusa against an EVTX file. */
function runHayabusa(filePath: string): EVTXDetection[] {
  const detections: EVTXDetection[] = [];

  if (!ensureHayabusaDirs()) return detections;

  const output = runTool(
    `hayabusa -f "${filePath}" -o "${HAYABUSA_OUTPUT}" -r "${HAYABUSA_RULES_DIR}" --no-color 2>&1`
  );

  // Try to parse JSON output
  try {
    if (existsSync(HAYABUSA_OUTPUT)) {
      const raw = readFileSync(HAYABUSA_OUTPUT, 'utf-8');
      const results = JSON.parse(raw);

      if (Array.isArray(results)) {
        for (const result of results) {
          detections.push({
            rule: result.RuleTitle || result.rule || 'Unknown Rule',
            severity: result.Level || result.level || 'info',
            category: result.Category || result.category || 'general',
            description: result.Details || result.details || '',
            events: [],
          });
        }
      }
    }
  } catch {
    // JSON parsing failed, try to parse console output
    if (output) {
      console.log('[JURI-X EVTX] Hayabusa ran but JSON output not parseable, using console output');
    }
  }

  return detections;
}

// ─── Fallback: Manual EVTX Parsing ──────────────────────────────────────────

/** Parse EVTX file using strings extraction and pattern matching. */
function parseEVTXManual(filePath: string): {
  events: EVTXEvent[];
  criticalEvents: EVTXEvent[];
  suspiciousEvents: EVTXEvent[];
  totalEvents: number;
} {
  const events: EVTXEvent[] = [];

  console.log('[JURI-X EVTX] Using manual string-based EVTX parser');

  // Extract strings from the EVTX file
  const stringsOutput = runTool(`strings -e l -n 4 "${filePath}" 2>/dev/null | head -20000`);
  if (!stringsOutput) {
    // Try UTF-8 extraction
    const utf8Output = runTool(`strings -n 4 "${filePath}" 2>/dev/null | head -20000`);
    if (!utf8Output) return { events: [], criticalEvents: [], suspiciousEvents: [], totalEvents: 0 };
    return parseStringOutput(utf8Output);
  }

  return parseStringOutput(stringsOutput);
}

/** Parse string output for event ID patterns. */
function parseStringOutput(stringsOutput: string): {
  events: EVTXEvent[];
  criticalEvents: EVTXEvent[];
  suspiciousEvents: EVTXEvent[];
  totalEvents: number;
} {
  const events: EVTXEvent[] = [];
  const lines = stringsOutput.split('\n');

  // Track event counts for brute force detection
  const failedLoginCount: { timestamp: string; account: string; source: string }[] = [];
  const processCreations: EVTXEvent[] = [];
  const serviceInstallations: EVTXEvent[] = [];
  const scheduledTasks: EVTXEvent[] = [];
  const auditLogCleared: EVTXEvent[] = [];
  const accountChanges: EVTXEvent[] = [];

  let eventCounter = 0;

  // Look for event ID patterns in the string output
  // Windows EVTX XML format contains EventID elements
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();

    // Match EventID patterns
    const eventIdMatch = line.match(/EventID(?:\s+QWORD)?\s*[">]*(\d{4,5})/);
    if (!eventIdMatch) continue;

    const eventId = parseInt(eventIdMatch[1], 10);
    const eventInfo = SECURITY_EVENT_IDS[eventId];
    if (!eventInfo) continue;

    eventCounter++;

    // Extract surrounding context for event data
    const contextStart = Math.max(0, i - 5);
    const contextEnd = Math.min(lines.length - 1, i + 15);
    const contextLines = lines.slice(contextStart, contextEnd + 1).join(' ');

    const eventData: Record<string, string> = {};

    // Extract common fields from context
    const accountMatch = contextLines.match(/TargetUserName[^>]*>([^<]+)/);
    if (accountMatch) eventData['TargetUserName'] = accountMatch[1];

    const sourceIPMatch = contextLines.match(/IpAddress[^>]*>([^<]+)/);
    if (sourceIPMatch) eventData['IpAddress'] = sourceIPMatch[1];

    const logonTypeMatch = contextLines.match(/LogonType[^>]*>([^<]+)/);
    if (logonTypeMatch) eventData['LogonType'] = logonTypeMatch[1];

    const processNameMatch = contextLines.match(/NewProcessName[^>]*>([^<]+)/);
    if (processNameMatch) eventData['NewProcessName'] = processNameMatch[1];

    const serviceNameMatch = contextLines.match(/ServiceName[^>]*>([^<]+)/);
    if (serviceNameMatch) eventData['ServiceName'] = serviceNameMatch[1];

    const imageNameMatch = contextLines.match(/ImageFileName[^>]*>([^<]+)/);
    if (imageNameMatch) eventData['ImageFileName'] = imageNameMatch[1];

    const timeCreatedMatch = contextLines.match(/TimeCreated\s+SystemTime=["']([^"']+)["']/);
    const timestamp = timeCreatedMatch ? timeCreatedMatch[1] : 'unknown';

    const event: EVTXEvent = {
      eventId,
      timestamp,
      level: eventInfo.level,
      description: eventInfo.description,
      data: eventData,
    };

    events.push(event);

    // Categorize events for analysis
    switch (eventId) {
      case 4625:
        failedLoginCount.push({
          timestamp,
          account: eventData['TargetUserName'] || 'unknown',
          source: eventData['IpAddress'] || 'unknown',
        });
        break;
      case 4688:
        processCreations.push(event);
        break;
      case 7045:
      case 4697:
        serviceInstallations.push(event);
        break;
      case 4698:
      case 4699:
      case 4700:
        scheduledTasks.push(event);
        break;
      case 1102:
        auditLogCleared.push(event);
        break;
      case 4720:
      case 4722:
      case 4724:
      case 4725:
      case 4726:
      case 4738:
      case 4741:
      case 4781:
        accountChanges.push(event);
        break;
    }
  }

  // Classify events
  const criticalEvents = events.filter(e => e.level === 'critical');
  const suspiciousEvents = events.filter(e =>
    e.level === 'critical' ||
    e.level === 'warning'
  );

  return { events, criticalEvents, suspiciousEvents, totalEvents: eventCounter };
}

// ─── Suspicious Finding Detection ───────────────────────────────────────────

function detectSuspiciousEVTX(
  events: EVTXEvent[],
  criticalEvents: EVTXEvent[],
  detections: EVTXDetection[],
): EVTXSuspiciousFinding[] {
  const findings: EVTXSuspiciousFinding[] = [];

  // Group events by EventID for analysis
  const eventsById = new Map<number, EVTXEvent[]>();
  for (const event of events) {
    if (!eventsById.has(event.eventId)) eventsById.set(event.eventId, []);
    eventsById.get(event.eventId)!.push(event);
  }

  // 1. Brute force detection — many failed logins (4625)
  const failedLogins = eventsById.get(4625) || [];
  if (failedLogins.length > 20) {
    // Check for high volume from single source
    const sourceCounts = new Map<string, number>();
    for (const event of failedLogins) {
      const source = event.data['IpAddress'] || event.data['TargetUserName'] || 'unknown';
      sourceCounts.set(source, (sourceCounts.get(source) || 0) + 1);
    }

    const topSource = Array.from(sourceCounts.entries()).sort((a, b) => b[1] - a[1])[0];

    findings.push({
      category: 'brute_force',
      severity: 'critical',
      title: `Brute force attack detected (${failedLogins.length} failed login attempts)`,
      description: `An extremely high number of failed login attempts (Event ID 4625) were detected, strongly suggesting a brute force password attack.`,
      evidence: `Total failed logins: ${failedLogins.length}${topSource ? `, Top source/target: ${topSource[0]} (${topSource[1]} attempts)` : ''}`,
    });
  } else if (failedLogins.length > 5) {
    findings.push({
      category: 'brute_force',
      severity: 'suspicious',
      title: `Possible brute force attack (${failedLogins.length} failed login attempts)`,
      description: `Multiple failed login attempts were detected, which may indicate a brute force password attack.`,
      evidence: `Failed logins: ${failedLogins.length}`,
    });
  }

  // 2. New service installations (7045, 4697) — critical
  const serviceEvents = [
    ...(eventsById.get(7045) || []),
    ...(eventsById.get(4697) || []),
  ];

  if (serviceEvents.length > 0) {
    const suspiciousServices = serviceEvents.filter(e => {
      const name = (e.data['ServiceName'] || e.data['ImageFileName'] || '').toLowerCase();
      // Known suspicious service patterns
      return (
        /powershell|cmd|wscript|cscript|regsvr32|rundll/i.test(name) ||
        /temp|appdata|users\\|public\\|programdata/i.test(name)
      );
    });

    if (suspiciousServices.length > 0) {
      findings.push({
        category: 'suspicious_service',
        severity: 'critical',
        title: `Suspicious service installations detected (${suspiciousServices.length} services)`,
        description: `New services were installed that use suspicious executable paths (PowerShell, CMD, temp directories, etc.). This is a common persistence mechanism used by malware.`,
        evidence: suspiciousServices.map(e =>
          `Service: ${e.data['ServiceName'] || 'N/A'}, Path: ${e.data['ImageFileName'] || e.data['NewProcessName'] || 'N/A'}`
        ).join('\n'),
      });
    } else {
      findings.push({
        category: 'new_service',
        severity: 'warning',
        title: `New service installations (${serviceEvents.length} services)`,
        description: `New services were installed on the system. While not inherently suspicious, new services should be reviewed as they can be used for persistence.`,
        evidence: serviceEvents.slice(0, 10).map(e =>
          `Service: ${e.data['ServiceName'] || 'N/A'}, Path: ${e.data['ImageFileName'] || 'N/A'}`
        ).join('\n'),
      });
    }
  }

  // 3. Audit log cleared (1102) — critical
  const auditCleared = eventsById.get(1102) || [];
  if (auditCleared.length > 0) {
    findings.push({
      category: 'audit_log_cleared',
      severity: 'critical',
      title: `Security audit log was cleared (${auditCleared.length} occurrence${auditCleared.length > 1 ? 's' : ''})`,
      description: `The security audit log was cleared, which is a strong indicator of anti-forensic activity. Attackers often clear logs to cover their tracks.`,
      evidence: auditCleared.map(e => `Timestamp: ${e.timestamp}`).join('\n'),
    });
  }

  // 4. Suspicious process creation (4688) — highly suspicious
  const processEvents = eventsById.get(4688) || [];
  const suspiciousProcesses = processEvents.filter(e => {
    const name = (e.data['NewProcessName'] || '').toLowerCase();
    return (
      /powershell.*-enc|powershell.*-w hidden|powershell.*-nop/i.test(name) ||
      /cmd.*\/c|cmd.*\/k/i.test(name) ||
      /certutil\.exe|bitsadmin\.exe|mshta\.exe|regsvr32\.exe/i.test(name) ||
      /wscript\.exe|cscript\.exe|rundll32\.exe/i.test(name) ||
      /psexec\.exe|wmic\.exe|schtasks\.exe/i.test(name) ||
      /temp\\|%temp%|%appdata%|appdata\\\/local\\\/temp/i.test(name)
    );
  });

  if (suspiciousProcesses.length > 0) {
    findings.push({
      category: 'suspicious_process',
      severity: 'highly_suspicious',
      title: `Suspicious process execution detected (${suspiciousProcesses.length} processes)`,
      description: `Processes with known LOLBins (Living Off the Land Binaries) or suspicious command-line arguments were created. These are commonly used in attacks for execution, persistence, and lateral movement.`,
      evidence: suspiciousProcesses.slice(0, 10).map(e =>
        `Process: ${e.data['NewProcessName'] || 'N/A'}, Time: ${e.timestamp}`
      ).join('\n'),
    });
  }

  // 5. Scheduled task creation/deletion (persistence) — suspicious
  const taskEvents = [
    ...(eventsById.get(4698) || []), // created
    ...(eventsById.get(4699) || []), // deleted
    ...(eventsById.get(4700) || []), // enabled
    ...(eventsById.get(4702) || []), // updated
  ];

  if (taskEvents.length > 5) {
    findings.push({
      category: 'scheduled_task_abuse',
      severity: 'suspicious',
      title: `Scheduled task manipulation detected (${taskEvents.length} events)`,
      description: `A high volume of scheduled task creation, deletion, or modification events were detected. Attackers commonly use scheduled tasks for persistence.`,
      evidence: taskEvents.slice(0, 10).map(e =>
        `${e.description}: ${e.timestamp}${e.data['TargetUserName'] ? ` (User: ${e.data['TargetUserName']})` : ''}`
      ).join('\n'),
    });
  } else if (taskEvents.length > 0) {
    findings.push({
      category: 'scheduled_task',
      severity: 'warning',
      title: `Scheduled task activity (${taskEvents.length} events)`,
      description: `Scheduled task creation or modification was detected. Review tasks for legitimacy.`,
      evidence: taskEvents.map(e => `${e.description}: ${e.timestamp}`).join('\n'),
    });
  }

  // 6. Account manipulation — suspicious
  const accountEvents = events.filter(e =>
    [4720, 4722, 4724, 4725, 4726, 4738, 4741, 4781].includes(e.eventId)
  );

  if (accountEvents.length > 3) {
    findings.push({
      category: 'account_manipulation',
      severity: 'suspicious',
      title: `Multiple account manipulation events (${accountEvents.length} events)`,
      description: `Multiple account creation, modification, deletion, or password reset events were detected. This may indicate privilege escalation or account takeover attempts.`,
      evidence: accountEvents.slice(0, 10).map(e =>
        `${e.description}: ${e.data['TargetUserName'] || 'unknown'} (${e.timestamp})`
      ).join('\n'),
    });
  }

  // 7. Firewall changes — suspicious
  const firewallEvents = events.filter(e =>
    [4946, 4950, 4952, 4956, 5025, 5031].includes(e.eventId)
  );

  if (firewallEvents.length > 0) {
    const firewallDisabled = firewallEvents.filter(e => e.eventId === 5025);
    if (firewallDisabled.length > 0) {
      findings.push({
        category: 'firewall_disabled',
        severity: 'critical',
        title: 'Windows Firewall was disabled',
        description: 'The Windows Firewall service was stopped, which may indicate an attacker disabling security controls.',
        evidence: firewallDisabled.map(e => `Timestamp: ${e.timestamp}`).join('\n'),
      });
    } else {
      findings.push({
        category: 'firewall_changes',
        severity: 'suspicious',
        title: `Firewall configuration changes (${firewallEvents.length} events)`,
        description: `Changes to the Windows Firewall configuration were detected, including rule modifications and exception list changes.`,
        evidence: firewallEvents.slice(0, 5).map(e => `${e.description}: ${e.timestamp}`).join('\n'),
      });
    }
  }

  // 8. Hayabusa detection results
  if (detections.length > 0) {
    const criticalDetections = detections.filter(d =>
      d.severity === 'critical' || d.severity === 'high'
    );

    if (criticalDetections.length > 0) {
      findings.push({
        category: 'hayabusa_detections',
        severity: 'critical',
        title: `Hayabusa detected ${criticalDetections.length} high-severity threats`,
        description: `Hayabusa sigma-based detection rules matched ${criticalDetections.length} high or critical severity events in the event log.`,
        evidence: criticalDetections.slice(0, 10).map(d =>
          `[${d.severity.toUpperCase()}] ${d.rule}: ${d.description} (${d.category})`
        ).join('\n'),
      });
    } else {
      findings.push({
        category: 'hayabusa_detections',
        severity: 'suspicious',
        title: `Hayabusa detected ${detections.length} events of interest`,
        description: `Hayabusa sigma-based detection rules matched ${detections.length} events in the event log.`,
        evidence: detections.slice(0, 10).map(d =>
          `[${d.severity.toUpperCase()}] ${d.rule}: ${d.description} (${d.category})`
        ).join('\n'),
      });
    }
  }

  // 9. Privilege assignment events
  const privilegeEvents = eventsById.get(4672) || [];
  if (privilegeEvents.length > 0) {
    const adminLogons = privilegeEvents.filter(e => {
      const privileges = Object.values(e.data).join(' ').toLowerCase();
      return /SeAssignPrimaryTokenPrivilege|SeTcbPrivilege|SeBackupPrivilege|SeRestorePrivilege|SeDebugPrivilege/i.test(privileges);
    });
    if (adminLogons.length > 0) {
      findings.push({
        category: 'privileged_logon',
        severity: 'suspicious',
        title: `Privileged logons with sensitive privileges (${adminLogons.length} events)`,
        description: `Logons with dangerous privileges (debug, backup, restore, TCB) were detected. These can be used for credential extraction and system compromise.`,
        evidence: adminLogons.slice(0, 5).map(e =>
          `User: ${e.data['TargetUserName'] || 'unknown'}, Time: ${e.timestamp}`
        ).join('\n'),
      });
    }
  }

  return findings;
}

// ─── Main Analysis Function ─────────────────────────────────────────────────

export function analyzeEVTX(filePath: string): EVTXResult {
  if (!existsSync(filePath)) {
    return {
      available: false,
      filePath,
      totalEvents: 0,
      criticalEvents: [],
      suspiciousEvents: [],
      detections: [],
      suspiciousFindings: [],
      toolUsed: 'none',
      errors: [`File not found: ${filePath}`],
    };
  }

  const fileStat = statSync(filePath);
  const fileName = basename(filePath);
  const errors: string[] = [];
  let toolUsed = 'none';

  console.log(`[JURI-X EVTX] Analyzing ${fileName} (${fileStat.size} bytes)`);

  let totalEvents = 0;
  let criticalEvents: EVTXEvent[] = [];
  let suspiciousEvents: EVTXEvent[] = [];
  let detections: EVTXDetection[] = [];

  // Try Hayabusa first
  if (isHayabusaAvailable()) {
    console.log('[JURI-X EVTX] Hayabusa is available, running analysis...');
    detections = runHayabusa(filePath);
    if (detections.length > 0) {
      toolUsed = 'hayabusa';
      console.log(`[JURI-X EVTX] Hayabusa: ${detections.length} detections`);
    } else {
      console.log('[JURI-X EVTX] Hayabusa: no detections');
      toolUsed = 'hayabusa';
    }
  }

  // Always run manual parsing as well (to get structured event data)
  console.log('[JURI-X EVTX] Running manual EVTX parsing...');
  const manualResult = parseEVTXManual(filePath);

  totalEvents = manualResult.totalEvents;
  criticalEvents = manualResult.criticalEvents;
  suspiciousEvents = manualResult.suspiciousEvents;

  if (toolUsed === 'none') {
    if (totalEvents > 0) {
      toolUsed = 'manual_parser';
      console.log(`[JURI-X EVTX] Manual parser: ${totalEvents} events extracted`);
    }
  } else {
    toolUsed = `${toolUsed}+manual`;
    console.log(`[JURI-X EVTX] Manual parser: ${totalEvents} additional events extracted`);
  }

  // Detect suspicious findings
  const allEvents = [...criticalEvents, ...suspiciousEvents];
  const suspiciousFindings = detectSuspiciousEVTX(allEvents, criticalEvents, detections);

  console.log(`[JURI-X EVTX] Analysis complete: ${totalEvents} events, ${criticalEvents.length} critical, ${detections.length} hayabusa detections, ${suspiciousFindings.length} findings`);

  return {
    available: toolUsed !== 'none',
    filePath,
    totalEvents,
    criticalEvents,
    suspiciousEvents,
    detections,
    suspiciousFindings,
    toolUsed,
    errors,
  };
}
