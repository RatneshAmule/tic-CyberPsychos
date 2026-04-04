// =============================================================================
// JURI-X — Keyword Intelligence Engine
// =============================================================================

import type { KeywordResult } from './types';
import { getSampleAnalysisResult } from './sample-data';

const DEFAULT_KEYWORDS = [
  'password',
  'admin',
  'bitcoin',
  '.onion',
  'confidential',
  'secret',
  'encrypt',
  'root',
  'backdoor',
  'malware',
  'exploit',
  'payload',
  'keylogger',
  'ransomware',
  'credential',
  'token',
  'api_key',
  'ssh',
  'privilege',
];

export function searchKeywords(
  _data: unknown[],
  keywords?: string[]
): KeywordResult[] {
  const result = getSampleAnalysisResult();
  if (keywords) {
    return result.keywordResults.filter((k) => keywords.includes(k.keyword));
  }
  return result.keywordResults;
}

export function getDefaultKeywords(): string[] {
  return DEFAULT_KEYWORDS;
}
