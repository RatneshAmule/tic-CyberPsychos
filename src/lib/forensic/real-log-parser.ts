import type { ActionCategory, SeverityLevel } from './types';

export interface ParsedLogEvent {
  timestamp: Date;
  action: ActionCategory;
  entity: string;
  description: string;
  source: string;
  severity: SeverityLevel;
  confidence: number;
  raw: string;
}

// Common log timestamp patterns
const TIMESTAMP_PATTERNS = [
  // ISO format: 2026-03-15T08:12:33.000Z or 2026-03-15 08:12:33
  { regex: /(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)/, priority: 10 },
  // Apache/Nginx: 15/Mar/2026:08:12:33
  { regex: /(\d{2}\/[A-Za-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2})/, priority: 8 },
  // Syslog: Mar 15 08:12:33
  { regex: /([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})/, priority: 7 },
  // Windows Event: [2026-03-15 08:12:33]
  { regex: /\[(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\]/, priority: 9 },
  // Brackets: <2026-03-15T08:12:33>
  { regex: /<(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})>/, priority: 9 },
  // Short: 2026-03-15 08:12:33
  { regex: /(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})/, priority: 8 },
  // Time only: 08:12:33
  { regex: /(\d{2}:\d{2}:\d{2}(?:\.\d+)?)/, priority: 3 },
];

// Suspicious keywords in log lines — ordered from most to least suspicious
const SUSPICIOUS_KEYWORDS: {
  pattern: RegExp;
  severity: SeverityLevel;
  action: ActionCategory;
}[] = [
  { pattern: /password|credential|secret|token|api[_-]?key/i, severity: 'critical', action: 'unknown' },
  { pattern: /malware|virus|trojan|backdoor|exploit|payload/i, severity: 'critical', action: 'file_executed' },
  { pattern: /rootkit|keylog|screen.*capture|spy/i, severity: 'critical', action: 'file_executed' },
  { pattern: /tor\b|onion|proxy\b|vpn|anonym/i, severity: 'critical', action: 'network_connection' },
  { pattern: /permission\s+denied|access\s+denied/i, severity: 'highly_suspicious', action: 'login_attempt' },
  { pattern: /download|upload|transfer|exfil/i, severity: 'highly_suspicious', action: 'data_exfiltration' },
  { pattern: /service\s+(start|stop|install)/i, severity: 'highly_suspicious', action: 'service_start' },
  { pattern: /encrypt|decrypt|cipher|aes|rsa/i, severity: 'highly_suspicious', action: 'file_executed' },
  { pattern: /bitcoin|crypto|wallet|monero/i, severity: 'highly_suspicious', action: 'unknown' },
  { pattern: /failed|failure|error|denied|unauthorized/i, severity: 'suspicious', action: 'login_attempt' },
  { pattern: /connection\s+(from|to|refused|reset|timeout)/i, severity: 'suspicious', action: 'network_connection' },
  { pattern: /block|drop|reject|firewall/i, severity: 'suspicious', action: 'network_connection' },
  { pattern: /exec|spawn|fork|create\s+process/i, severity: 'suspicious', action: 'process_created' },
  { pattern: /delete|remove|unlink|rm\s+/i, severity: 'suspicious', action: 'file_deleted' },
  { pattern: /ssh|telnet|ftp|rlogin/i, severity: 'suspicious', action: 'network_connection' },
  { pattern: /sudo|su\s+|runas|privilege/i, severity: 'suspicious', action: 'login_attempt' },
  { pattern: /usb|removable|mount|umount/i, severity: 'suspicious', action: 'usb_connected' },
  { pattern: /registry|reg\s+|hk lm|hkcu|hive/i, severity: 'suspicious', action: 'registry_change' },
  { pattern: /driver|\.sys|\.dll/i, severity: 'suspicious', action: 'driver_loaded' },
  { pattern: /shutdown|restart|reboot/i, severity: 'benign', action: 'system_shutdown' },
  { pattern: /login|logon|auth|sign/i, severity: 'benign', action: 'login_attempt' },
  { pattern: /open|read|access/i, severity: 'benign', action: 'file_opened' },
  { pattern: /write|create|copy|move/i, severity: 'benign', action: 'file_created' },
  { pattern: /modify|change|update/i, severity: 'benign', action: 'file_modified' },
];

function parseTimestamp(line: string): Date | null {
  for (const { regex } of TIMESTAMP_PATTERNS) {
    const match = line.match(regex);
    if (match) {
      try {
        let ts = match[1];
        // Handle Apache/Nginx short month names: 15/Mar/2026:08:12:33
        if (/\d{2}\/[A-Za-z]{3}\/\d{4}/.test(ts)) {
          const d = new Date(ts.replace(/(\d{2})\/([A-Za-z]{3})\/(\d{4})/, '$2 $1, $3'));
          if (!isNaN(d.getTime())) return d;
        }
        // Handle plain date-time without T separator
        if (!ts.includes('T') && !ts.includes('Z') && /^\d{4}-\d{2}-\d{2}\s/.test(ts)) {
          ts = ts.replace(' ', 'T');
        }
        const d = new Date(ts);
        if (!isNaN(d.getTime())) return d;
      } catch {
        /* continue to next pattern */
      }
    }
  }
  return null;
}

function classifyLine(line: string): {
  action: ActionCategory;
  severity: SeverityLevel;
  confidence: number;
} {
  for (const kw of SUSPICIOUS_KEYWORDS) {
    if (kw.pattern.test(line)) {
      const confidence =
        kw.severity === 'critical' ? 0.9 : kw.severity === 'highly_suspicious' ? 0.8 : 0.7;
      return { action: kw.action, severity: kw.severity, confidence };
    }
  }
  return { action: 'unknown', severity: 'benign', confidence: 0.5 };
}

export function parseLogFile(
  content: string,
  sourceName: string
): ParsedLogEvent[] {
  const lines = content.split('\n');
  const events: ParsedLogEvent[] = [];

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.length < 5) continue;

    const timestamp = parseTimestamp(trimmed);
    const { action, severity, confidence } = classifyLine(trimmed);

    // Extract entity (IP, file path, username)
    let entity = 'unknown';
    const ipMatch = trimmed.match(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/);
    const fileMatch = trimmed.match(/(?:\/[\w.\-]+){2,}/);
    const userMatch = trimmed.match(/(?:user[=:\s]+)(\w+)/i);

    if (ipMatch) entity = ipMatch[1];
    else if (fileMatch) entity = fileMatch[0].substring(0, 80);
    else if (userMatch) entity = userMatch[1];
    else {
      // Take first meaningful words after timestamp portion
      const stripped = trimmed.replace(
        /[\[\]<>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z:+\s]+/,
        ''
      );
      const words = stripped.split(/\s+/);
      entity = words.slice(0, 3).join(' ').substring(0, 80);
    }

    events.push({
      timestamp: timestamp || new Date(),
      action,
      entity: entity.substring(0, 100),
      description: trimmed.substring(0, 500),
      source: sourceName,
      severity,
      confidence,
      raw: trimmed,
    });
  }

  return events;
}
