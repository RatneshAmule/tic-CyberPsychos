import { execSync } from 'child_process';
import { existsSync } from 'fs';

export interface StringMatch {
  offset: number;
  string: string;
  encoding: 'ascii' | 'utf8' | 'unicode';
}

// Use the real `strings` command for extraction
export function extractStrings(filePath: string, minLength: number = 4): string[] {
  try {
    if (!existsSync(filePath)) return [];
    const output = execSync(`strings -n ${minLength} "${filePath}"`, {
      encoding: 'utf-8',
      maxBuffer: 200 * 1024 * 1024, // 200MB — large disk images can produce huge string output
      timeout: 60000, // 60 seconds
    });
    // Limit to first 100K strings to prevent memory issues
    const lines = output.split('\n').filter(s => s.trim().length > 0);
    return lines.length > 100000 ? lines.slice(0, 100000) : lines;
  } catch (err: any) {
    // If maxBuffer exceeded, try with shorter strings
    if (err?.message?.includes('maxBuffer')) {
      try {
        console.warn(`[JURI-X] strings maxBuffer exceeded, retrying with min length 6`);
        const output = execSync(`strings -n 6 "${filePath}" 2>/dev/null | head -50000`, {
          encoding: 'utf-8',
          maxBuffer: 100 * 1024 * 1024,
          timeout: 60000,
        });
        return output.split('\n').filter(s => s.trim().length > 0);
      } catch {
        return [];
      }
    }
    return [];
  }
}

// Extract strings with offsets using the real `strings` command
export function extractStringsWithOffsets(
  filePath: string,
  minLength: number = 4
): StringMatch[] {
  try {
    if (!existsSync(filePath)) return [];
    const output = execSync(`strings -n ${minLength} -t x "${filePath}"`, {
      encoding: 'utf-8',
      maxBuffer: 50 * 1024 * 1024,
      timeout: 30000,
    });
    return output
      .split('\n')
      .filter(s => s.trim())
      .map((line): StringMatch | null => {
        const match = line.match(/^\s*([0-9a-f]+)\s+(.*)$/);
        if (match) {
          return {
            offset: parseInt(match[1], 16),
            string: match[2],
            encoding: 'ascii',
          };
        }
        return null;
      })
      .filter((s): s is StringMatch => s !== null);
  } catch {
    return [];
  }
}

// Search for specific strings (keywords) in extracted strings
export function searchStringsForKeywords(
  extractedStrings: string[],
  keywords: string[]
): {
  keyword: string;
  matches: { string: string; index: number }[];
  totalMatches: number;
}[] {
  return keywords
    .map(keyword => {
      const lowerKeyword = keyword.toLowerCase();
      const matches = extractedStrings
        .map((s, i) => ({ string: s, index: i }))
        .filter(m => m.string.toLowerCase().includes(lowerKeyword));
      return {
        keyword,
        matches: matches.slice(0, 100), // Limit to 100 per keyword
        totalMatches: matches.length,
      };
    })
    .filter(r => r.totalMatches > 0);
}
