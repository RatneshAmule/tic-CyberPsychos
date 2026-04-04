import { existsSync } from 'fs';
import { execSync } from 'child_process';

// ─── ZERO native module imports ───────────────────────────────────────────────
// PERMANENT FIX: Uses sqlite3 CLI tool instead of better-sqlite3 native module.
// sqlite3 is pre-installed on Kali Linux. No compilation needed.

export interface BrowserHistoryEntry {
  url: string;
  title: string;
  visitCount: number;
  lastVisitTime: string;
  typedCount: number;
}

export interface BookmarkEntry {
  url: string;
  title: string;
  dateAdded: string;
  folder: string;
}

export interface DownloadEntry {
  url: string;
  targetPath: string;
  startTime: string;
  receivedBytes: number;
  totalBytes: number;
  mimeType: string;
}

export interface SQLiteParseResult {
  databaseType:
    | 'chrome_history'
    | 'firefox_history'
    | 'chrome_downloads'
    | 'generic'
    | 'unknown';
  tables: string[];
  history: BrowserHistoryEntry[];
  downloads: DownloadEntry[];
  bookmarks: BookmarkEntry[];
  rowCount: Record<string, number>;
  suspiciousUrls: { url: string; title: string; reason: string }[];
}

const SUSPICIOUS_URL_PATTERNS = [
  { pattern: /\.onion/i, reason: 'Tor hidden service (.onion)' },
  { pattern: /torproject\.org/i, reason: 'Tor Project website' },
  { pattern: /darknet|blackmarket|silk.?road/i, reason: 'Darknet marketplace reference' },
  { pattern: /hack|exploit|malware|virus/i, reason: 'Security threat reference' },
  { pattern: /bitcoin|cryptocurrency|wallet/i, reason: 'Cryptocurrency reference' },
  { pattern: /password|credential|leak/i, reason: 'Credential-related content' },
  { pattern: /phishing|scam|fraud/i, reason: 'Fraud/phishing reference' },
  { pattern: /keygen|crack|serial/i, reason: 'Software piracy' },
  { pattern: /anonymous|proxy|vpn/i, reason: 'Anonymity tool reference' },
];

/** Safe exec — never throws, returns null on failure */
function safeSqlite3(sql: string, dbPath: string): string | null {
  try {
    return execSync(`sqlite3 "${dbPath}" "${sql}"`, {
      encoding: 'utf-8',
      maxBuffer: 50 * 1024 * 1024,
      timeout: 30000,
    }).trim();
  } catch {
    return null;
  }
}

function detectDatabaseType(tables: string[]): string {
  if (tables.includes('urls') && tables.includes('visits')) return 'chrome_history';
  if (tables.includes('moz_places') && tables.includes('moz_historyvisits')) return 'firefox_history';
  if (tables.includes('downloads')) return 'chrome_downloads';
  if (tables.length > 0) return 'generic';
  return 'unknown';
}

function checkSuspicious(url: string, title: string): string | null {
  for (const sp of SUSPICIOUS_URL_PATTERNS) {
    if (sp.pattern.test(url) || sp.pattern.test(title)) {
      return sp.reason;
    }
  }
  return null;
}

export async function parseSqliteDatabase(filePath: string): Promise<SQLiteParseResult> {
  const empty: SQLiteParseResult = {
    databaseType: 'unknown',
    tables: [],
    history: [],
    downloads: [],
    bookmarks: [],
    rowCount: {},
    suspiciousUrls: [],
  };

  try {
    if (!existsSync(filePath)) return empty;

    // Check if sqlite3 CLI is available
    try {
      execSync('which sqlite3', { encoding: 'utf-8' });
    } catch {
      console.warn('[JURI-X] sqlite3 CLI not found — SQLite analysis disabled');
      return empty;
    }

    // Get table list
    const tablesOutput = safeSqlite3(
      "SELECT name FROM sqlite_master WHERE type='table';",
      filePath
    );
    if (!tablesOutput) return empty;

    const tables = tablesOutput.split('\n').map(t => t.trim()).filter(Boolean);
    const dbType = detectDatabaseType(tables) as SQLiteParseResult['databaseType'];

    // Get row counts
    const rowCount: Record<string, number> = {};
    for (const table of tables) {
      try {
        const countOutput = safeSqlite3(`SELECT COUNT(*) FROM "${table}";`, filePath);
        rowCount[table] = countOutput ? parseInt(countOutput, 10) : -1;
      } catch {
        rowCount[table] = -1;
      }
    }

    const history: BrowserHistoryEntry[] = [];
    const downloads: DownloadEntry[] = [];
    const suspiciousUrls: { url: string; title: string; reason: string }[] = [];

    // --- Chrome History ---
    if (dbType === 'chrome_history') {
      // Parse history using sqlite3 CSV output mode
      const historyOutput = safeSqlite3(
        `SELECT url, title, visit_count, typed_count,
           datetime(last_visit_time / 1000000 - 11644473600, 'unixepoch') as last_visit
         FROM urls ORDER BY last_visit_time DESC LIMIT 500;`,
        filePath
      );
      if (historyOutput) {
        for (const line of historyOutput.split('\n')) {
          // sqlite3 default separator is |
          const parts = line.split('|');
          if (parts.length >= 4) {
            const url = parts[0] || '';
            const title = parts[1] || '';
            history.push({
              url,
              title,
              visitCount: parseInt(parts[2], 10) || 0,
              lastVisitTime: parts[4] || '',
              typedCount: parseInt(parts[3], 10) || 0,
            });

            const reason = checkSuspicious(url, title);
            if (reason) {
              suspiciousUrls.push({ url, title, reason });
            }
          }
        }
      }

      // Parse downloads
      const dlOutput = safeSqlite3(
        `SELECT url, target_path, received_bytes, total_bytes,
           datetime(start_time / 1000000 - 11644473600, 'unixepoch') as start_time, mime_type
         FROM downloads ORDER BY start_time DESC LIMIT 200;`,
        filePath
      );
      if (dlOutput) {
        for (const line of dlOutput.split('\n')) {
          const parts = line.split('|');
          if (parts.length >= 5) {
            downloads.push({
              url: parts[0] || '',
              targetPath: parts[1] || '',
              startTime: parts[4] || '',
              receivedBytes: parseInt(parts[2], 10) || 0,
              totalBytes: parseInt(parts[3], 10) || 0,
              mimeType: parts[5] || '',
            });
          }
        }
      }
    }

    // --- Firefox History ---
    if (dbType === 'firefox_history') {
      const historyOutput = safeSqlite3(
        `SELECT url, title, visit_count,
           datetime(last_visit_date / 1000000, 'unixepoch') as last_visit
         FROM moz_places ORDER BY last_visit_date DESC LIMIT 500;`,
        filePath
      );
      if (historyOutput) {
        for (const line of historyOutput.split('\n')) {
          const parts = line.split('|');
          if (parts.length >= 3) {
            const url = parts[0] || '';
            const title = parts[1] || '';
            history.push({
              url,
              title,
              visitCount: parseInt(parts[2], 10) || 0,
              lastVisitTime: parts[3] || '',
              typedCount: 0,
            });

            const reason = checkSuspicious(url, title);
            if (reason) {
              suspiciousUrls.push({ url, title, reason });
            }
          }
        }
      }
    }

    return {
      databaseType: dbType,
      tables,
      history,
      downloads,
      bookmarks: [],
      rowCount,
      suspiciousUrls,
    };
  } catch (error) {
    console.error(`SQLite parse failed for ${filePath}:`, error);
    return empty;
  }
}
