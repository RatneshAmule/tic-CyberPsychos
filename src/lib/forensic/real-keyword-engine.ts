import { existsSync } from 'fs';
import { execSync } from 'child_process';
import path from 'path';

export interface KeywordSearchResult {
  keyword: string;
  matches: {
    file: string;
    line: number;
    context: string;
    source: string;
  }[];
  totalMatches: number;
}

export const FORENSIC_KEYWORDS = [
  'password', 'passwd', 'pwd',
  'admin', 'root', 'sudo', 'su ',
  'bitcoin', 'btc', 'monero', 'xmr',
  '.onion', 'tor ', 'proxy',
  'credential', 'secret', 'token',
  'api_key', 'apikey', 'api-key',
  'ssh', 'private_key', 'rsa',
  'backdoor', 'rootkit', 'keylog',
  'malware', 'trojan', 'exploit',
  'payload', 'shellcode', 'inject',
  'encrypt', 'decrypt', 'cipher',
  'exfil', 'upload', 'steal',
  'hack', 'crack', 'bypass',
  'database', 'dump', 'sql',
  'shadow', 'hashcat', 'john',
];

// Real ripgrep-based search across a directory of files
export function searchKeywordsInFiles(
  directory: string,
  keywords?: string[]
): KeywordSearchResult[] {
  try {
    if (!existsSync(directory)) return [];

    const searchKeywords = keywords || FORENSIC_KEYWORDS;
    const results: KeywordSearchResult[] = [];

    for (const keyword of searchKeywords) {
      try {
        // Use ripgrep for fast search
        const output = execSync(
          `rg -n --no-heading -i "${keyword.replace(/"/g, '\\"')}" "${directory}" 2>/dev/null || true`,
          { encoding: 'utf-8', maxBuffer: 10 * 1024 * 1024, timeout: 15000 }
        );

        const lines = output.split('\n').filter(l => l.trim());
        if (lines.length === 0) continue;

        const matches = lines.slice(0, 200).map(line => {
          const colonIdx = line.indexOf(':');
          const file = colonIdx > 0 ? line.substring(0, colonIdx) : 'unknown';
          const rest = colonIdx > 0 ? line.substring(colonIdx + 1) : line;
          const lineNumMatch = rest.match(/^(\d+):/);
          const lineNum = lineNumMatch ? parseInt(lineNumMatch[1]) : 0;
          const context = lineNumMatch ? rest.substring(lineNumMatch[0].length) : rest;
          return {
            file: path.basename(file),
            line: lineNum,
            context: context.trim().substring(0, 300),
            source: path.basename(path.dirname(file)),
          };
        });

        results.push({
          keyword,
          matches,
          totalMatches: lines.length,
        });
      } catch {
        // rg returns non-zero if no matches, that's fine
      }
    }

    return results.sort((a, b) => b.totalMatches - a.totalMatches);
  } catch (error) {
    console.error('Keyword search failed:', error);
    return [];
  }
}

// Search within a single file content string
export function searchKeywordsInContent(
  content: string,
  fileName: string,
  keywords?: string[]
): KeywordSearchResult[] {
  const searchKeywords = keywords || FORENSIC_KEYWORDS;
  const lines = content.split('\n');
  const results: KeywordSearchResult[] = [];

  for (const keyword of searchKeywords) {
    const matches: KeywordSearchResult['matches'] = [];
    const lowerKeyword = keyword.toLowerCase();

    lines.forEach((line, idx) => {
      if (line.toLowerCase().includes(lowerKeyword)) {
        matches.push({
          file: fileName,
          line: idx + 1,
          context: line.trim().substring(0, 300),
          source: fileName,
        });
      }
    });

    if (matches.length > 0) {
      results.push({
        keyword,
        matches: matches.slice(0, 100),
        totalMatches: matches.length,
      });
    }
  }

  return results.sort((a, b) => b.totalMatches - a.totalMatches);
}
