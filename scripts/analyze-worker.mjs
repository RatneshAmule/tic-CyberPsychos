#!/usr/bin/env node
/**
 * JURI-X Forensic Analysis Worker
 *
 * Standalone ESM script — runs in a SEPARATE process outside of Turbopack.
 * ZERO native module dependencies. All analysis uses CLI tools:
 *   - sqlite3 (for database parsing)
 *   - exiftool (for image EXIF/metadata)
 *   - identify/ImageMagick (for image dimensions)
 *   - strings, file, binwalk, mmls, fls, vol, tshark, etc.
 *
 * Usage: node scripts/analyze-worker.mjs /tmp/recon-x/evidence/<caseId>
 * Output: JSON result to stdout
 *
 * This script is NEVER processed by Turbopack/Next.js bundler.
 */

import { createHash } from 'crypto';
import { createReadStream } from 'fs';
import {
  existsSync, mkdirSync, readdirSync, statSync,
  openSync, closeSync, readSync, readFileSync, writeFileSync,
} from 'fs';
import { join, extname, basename } from 'path';
import { execSync } from 'child_process';
import { open } from 'fs/promises';

// ─── ZERO native module imports ─────────────────────────────────────────────
// All forensic analysis uses CLI tools pre-installed on Kali Linux.
// No better-sqlite3, no sharp, no exifr, no prisma — ever.

// ═══════════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════════

const EVIDENCE_DIR = '/tmp/recon-x/evidence';
const MAX_TEXT_READ = 10 * 1024 * 1024;

const FORENSIC_KEYWORDS = [
  'password', 'passwd', 'pwd', 'admin', 'root', 'sudo', 'su ',
  'bitcoin', 'btc', 'monero', 'xmr', '.onion', 'tor ', 'proxy',
  'credential', 'secret', 'token', 'api_key', 'apikey', 'api-key',
  'ssh', 'private_key', 'rsa', 'backdoor', 'rootkit', 'keylog',
  'malware', 'trojan', 'exploit', 'payload', 'shellcode', 'inject',
  'encrypt', 'decrypt', 'cipher', 'exfil', 'upload', 'steal',
  'hack', 'crack', 'bypass', 'database', 'dump', 'sql',
  'shadow', 'hashcat', 'john',
];

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

const MAGIC_BYTES = [
  { bytes: [0x50, 0x4B, 0x03, 0x04], offset: 0, type: 'archive', description: 'ZIP Archive (also Office docs, APK, JAR)' },
  { bytes: [0x25, 0x50, 0x44, 0x46], offset: 0, type: 'document', description: 'PDF Document' },
  { bytes: [0x89, 0x50, 0x4E, 0x47], offset: 0, type: 'image', description: 'PNG Image' },
  { bytes: [0xFF, 0xD8, 0xFF], offset: 0, type: 'image', description: 'JPEG Image' },
  { bytes: [0x47, 0x49, 0x46], offset: 0, type: 'image', description: 'GIF Image' },
  { bytes: [0x42, 0x4D], offset: 0, type: 'image', description: 'BMP Image' },
  { bytes: [0x49, 0x44, 0x33], offset: 0, type: 'audio', description: 'MP3 Audio (ID3)' },
  { bytes: [0x1A, 0x45, 0xDF, 0xA3], offset: 0, type: 'video', description: 'MKV/WebM Video' },
  { bytes: [0x00, 0x00, 0x00, 0x1C, 0x66, 0x74, 0x79, 0x70], offset: 4, type: 'video', description: 'MP4 Video' },
  { bytes: [0x52, 0x49, 0x46, 0x46], offset: 0, type: 'image', description: 'WebP Image' },
  { bytes: [0x45, 0x4C, 0x46], offset: 0, type: 'executable', description: 'ELF Binary (Linux)' },
  { bytes: [0x4D, 0x5A], offset: 0, type: 'executable', description: 'PE/EXE Binary (Windows)' },
  { bytes: [0x7F, 0x45, 0x4C, 0x46], offset: 0, type: 'executable', description: 'ELF Binary' },
  { bytes: [0xD0, 0xCF, 0x11, 0xE0], offset: 0, type: 'document', description: 'MS Compound File (DOC/XLS/PPT)' },
  { bytes: [0x50, 0x4F, 0x51, 0x53], offset: 0, type: 'filesystem', description: 'PFS/Ext2/3 filesystem' },
  { bytes: [0x45, 0x56, 0x46, 0x09, 0x0D, 0x0A], offset: 0, type: 'disk_image', description: 'EnCase E01 Image' },
  { bytes: [0x1F, 0x8B], offset: 0, type: 'archive', description: 'GZIP Compressed' },
  { bytes: [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07], offset: 0, type: 'archive', description: 'RAR Archive' },
  { bytes: [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C], offset: 0, type: 'archive', description: '7-Zip Archive' },
  { bytes: [0x53, 0x51, 0x4C, 0x69], offset: 0, type: 'database', description: 'SQLite Database' },
  { bytes: [0xD4, 0xC3, 0xB2, 0xA1], offset: 0, type: 'network_capture', description: 'PCAP Network Capture (little-endian)' },
  { bytes: [0xA1, 0xB2, 0xC3, 0xD4], offset: 0, type: 'network_capture', description: 'PCAP Network Capture (big-endian)' },
  { bytes: [0x0D, 0x0D, 0x0D, 0x0A], offset: 0, type: 'registry_hive', description: 'Windows Registry Hive' },
  { bytes: [0x4D, 0x41, 0x43, 0x43], offset: 0, type: 'disk_image', description: 'MAC OS X Disk Image' },
  { bytes: [0x56, 0x43, 0x44], offset: 40, type: 'disk_image', description: 'VirtualPC Disk Image' },
  { bytes: [0x78, 0x56, 0x34, 0x12], offset: 0, type: 'memory_dump', description: 'Windows Crash Dump / hibernation' },
  { bytes: [0xEB, 0x3C, 0x90], offset: 0, type: 'disk_image', description: 'Possible boot sector / disk image (x86 JMP)' },
  { bytes: [0xEB, 0x58, 0x90], offset: 0, type: 'disk_image', description: 'Possible FAT32 boot sector' },
  { bytes: [0xEB, 0x52, 0x90], offset: 0, type: 'disk_image', description: 'Possible NTFS boot sector' },
  { bytes: [0x4B, 0x44, 0x4D], offset: 0, type: 'disk_image', description: 'VMware VMDK Disk Image' },
  { bytes: [0x51, 0x46, 0x49, 0xFB], offset: 0, type: 'disk_image', description: 'QCOW2 Disk Image' },
  { bytes: [0x7F, 0x10, 0xDA, 0xBE], offset: 0, type: 'disk_image', description: 'VirtualBox VDI Disk Image' },
];

const LOG_TIMESTAMP_PATTERNS = [
  { regex: /(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)/, priority: 10 },
  { regex: /(\d{2}\/[A-Za-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2})/, priority: 8 },
  { regex: /([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})/, priority: 7 },
  { regex: /\[(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\]/, priority: 9 },
  { regex: /<(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})>/, priority: 9 },
  { regex: /(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})/, priority: 8 },
  { regex: /(\d{2}:\d{2}:\d{2}(?:\.\d+)?)/, priority: 3 },
];

const LOG_SUSPICIOUS_KEYWORDS = [
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

const EXEC_OPTS = {
  encoding: 'utf-8',
  maxBuffer: 50 * 1024 * 1024,
  timeout: 60000,
};

const LONG_EXEC_OPTS = {
  encoding: 'utf-8',
  maxBuffer: 50 * 1024 * 1024,
  timeout: 120000,
};

// ═══════════════════════════════════════════════════════════════════════════════
// UTILITY FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════════

function formatSize(bytes) {
  if (bytes === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return `${(bytes / Math.pow(1024, i)).toFixed(1)} ${units[i]}`;
}

function ensureDir(dir) {
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
}

function safeRun(cmd, opts = EXEC_OPTS) {
  try {
    return execSync(cmd, opts).trim();
  } catch {
    return null;
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// HASH CALCULATION
// ═══════════════════════════════════════════════════════════════════════════════

function calculateFileHash(filePath, algorithm = 'sha256') {
  return new Promise((resolve, reject) => {
    const hash = createHash(algorithm);
    const stream = createReadStream(filePath);
    stream.on('data', (data) => hash.update(data));
    stream.on('end', () => resolve(`${algorithm}:${hash.digest('hex')}`));
    stream.on('error', reject);
  });
}

// ═══════════════════════════════════════════════════════════════════════════════
// MAGIC BYTES DETECTION
// ═══════════════════════════════════════════════════════════════════════════════

function detectMagicBytes(buffer) {
  for (const sig of MAGIC_BYTES) {
    if (buffer.length < sig.offset + sig.bytes.length) continue;
    let match = true;
    for (let i = 0; i < sig.bytes.length; i++) {
      if (buffer[sig.offset + i] !== sig.bytes[i]) { match = false; break; }
    }
    if (match) return { type: sig.type, description: sig.description };
  }
  return null;
}

// ═══════════════════════════════════════════════════════════════════════════════
// ENTROPY CALCULATION
// ═══════════════════════════════════════════════════════════════════════════════

function calculateEntropy(buffer) {
  const freq = new Map();
  for (const byte of buffer) freq.set(byte, (freq.get(byte) || 0) + 1);
  let entropy = 0;
  const len = buffer.length;
  if (len === 0) return 0;
  for (const count of freq.values()) {
    const p = count / len;
    if (p > 0) entropy -= p * Math.log2(p);
  }
  return entropy;
}

function classifyEntropy(entropy) {
  if (entropy < 5) return 'low';
  if (entropy < 6.5) return 'medium';
  if (entropy < 7.5) return 'high';
  return 'very_high';
}

// ═══════════════════════════════════════════════════════════════════════════════
// FILE ANALYSIS (magic bytes, entropy, disk info, file command)
// ═══════════════════════════════════════════════════════════════════════════════

async function readFileHead(filePath, maxBytes = 512) {
  const handle = await open(filePath, 'r');
  try {
    const stat = await handle.stat();
    const toRead = Math.min(maxBytes, stat.size);
    const buf = Buffer.alloc(toRead);
    await handle.read(buf, 0, toRead, 0);
    return buf;
  } finally {
    await handle.close();
  }
}

async function readFileSample(filePath, sampleSize = 100000) {
  const handle = await open(filePath, 'r');
  try {
    const stat = await handle.stat();
    const toRead = Math.min(sampleSize, stat.size);
    if (stat.size <= sampleSize) {
      const buf = Buffer.alloc(toRead);
      await handle.read(buf, 0, toRead, 0);
      return buf;
    }
    const third = Math.floor(toRead / 3);
    const buf = Buffer.alloc(toRead);
    await handle.read(buf, 0, third, 0);
    const midOffset = Math.floor(stat.size / 2) - Math.floor(third / 2);
    await handle.read(buf, third, third, midOffset);
    const endOffset = stat.size - third;
    await handle.read(buf, third * 2, toRead - third * 2, Math.max(0, endOffset));
    return buf;
  } finally {
    await handle.close();
  }
}

function analyzeDiskImage(filePath) {
  const info = {};

  // file command
  try {
    const fileOutput = safeRun(`file -b "${filePath}"`, { ...EXEC_OPTS, timeout: 10000 });
    if (fileOutput?.toLowerCase().includes('partition')) info.partitionTable = fileOutput.substring(0, 200);
    if (fileOutput?.toLowerCase().match(/filesystem|ext|ntfs|fat/)) {
      info.fileSystems = fileOutput.match(/(ext[234]|ntfs|fat[123x]+|hfs\+?|apfs|btrfs|xfs|reiser|ufs)/gi)?.map(s => s.toUpperCase()) || [];
    }
  } catch { /* ignore */ }

  // fdisk/sfdisk
  try {
    const fdiskOutput = safeRun(`fdisk -l "${filePath}" 2>/dev/null || sfdisk -l "${filePath}" 2>/dev/null`, { ...LONG_EXEC_OPTS, timeout: 15000 });
    if (fdiskOutput && (fdiskOutput.includes('Device') || fdiskOutput.includes('Start'))) {
      info.partitionTable = info.partitionTable || 'Detected';
      info.partitions = [];
      for (const line of fdiskOutput.split('\n')) {
        const parts = line.trim().split(/\s+/);
        if (parts.length >= 5 && parts[0] && /^\//.test(parts[0])) {
          info.partitions.push({ id: parts[0], start: parts[1], end: parts[2], size: parts[3], type: parts[4], system: parts.slice(5).join(' ') || '' });
        }
        if (parts.length >= 4 && /^\d+$/.test(parts[0]) && parts[1].match(/^\d+$/) && parts[2].match(/^\d+$/)) {
          info.partitions.push({ id: `Partition ${parts[0]}`, start: parts[1], end: parts[2], size: parts[3], type: parts[4] || '', system: parts.slice(5).join(' ') || '' });
        }
      }
    }
  } catch { /* ignore */ }

  // mmls (Sleuth Kit)
  try {
    const mmlsOutput = safeRun(`mmls "${filePath}" 2>/dev/null`, LONG_EXEC_OPTS);
    if (mmlsOutput?.includes('DOS')) {
      if (!info.partitionTable) info.partitionTable = 'MBR (detected by sleuthkit)';
      info.partitions = [];
      for (const line of mmlsOutput.split('\n')) {
        const parts = line.trim().split(/\s+/);
        if (parts.length >= 5 && /^\d+:/.test(parts[0])) {
          info.partitions.push({ id: parts[0], start: parts[1], end: parts[2], size: parts[3], type: '', system: parts.slice(5).join(' ') || parts[4] });
        }
      }
    }
  } catch { /* ignore */ }

  // fls
  try {
    const flsOutput = safeRun(`fls -r -p "${filePath}" 2>/dev/null | head -100`, LONG_EXEC_OPTS);
    if (flsOutput?.trim().length > 0) {
      const files = flsOutput.split('\n').filter(l => l.trim()).length;
      if (files > 5) info.volumeLabel = `Contains approximately ${files} file entries`;
    }
  } catch { /* ignore */ }

  // blkid
  try {
    const blkidOutput = safeRun(`blkid "${filePath}" 2>/dev/null || file -s "${filePath}" 2>/dev/null`, { ...EXEC_OPTS, timeout: 10000 });
    if (blkidOutput?.toLowerCase().includes('label')) {
      const labelMatch = blkidOutput.match(/LABEL=["']?([^"'\s]+)/i);
      if (labelMatch) info.volumeLabel = labelMatch[1];
    }
  } catch { /* ignore */ }

  if (!info.partitionTable && !info.fileSystems?.length && !info.partitions?.length && !info.volumeLabel) return null;
  return info;
}

async function analyzeFile(filePath) {
  const fileStat = statSync(filePath);
  const headerBuffer = await readFileHead(filePath, 512);
  const magic = detectMagicBytes(headerBuffer);
  const entropySample = await readFileSample(filePath, 100000);
  const entropy = calculateEntropy(entropySample);
  const entropyLevel = classifyEntropy(entropy);

  let fileCommand = 'unknown';
  try {
    fileCommand = safeRun(`file -b "${filePath}"`, { ...EXEC_OPTS, timeout: 5000 }) || 'unknown';
  } catch { /* ignore */ }

  let stringsCount = 0;
  let inString = false;
  let strLen = 0;
  for (const byte of entropySample) {
    if (byte >= 32 && byte <= 126) {
      strLen++;
      if (!inString && strLen >= 4) { stringsCount++; inString = true; }
    } else {
      if (inString) inString = false;
      strLen = 0;
    }
  }

  const fileName = basename(filePath).toLowerCase();
  const isExecutable = magic?.type === 'executable' || fileName.endsWith('.exe') || fileName.endsWith('.dll') || fileName.endsWith('.sys');
  const isCompressed = magic?.type === 'archive' && (magic.description.includes('GZIP') || magic.description.includes('RAR') || magic.description.includes('7-Zip'));
  const isImage = magic?.type === 'image' || ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.tiff', '.svg'].some(ext => fileName.endsWith(ext));
  const isDocument = magic?.type === 'document' || ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.txt', '.rtf'].some(ext => fileName.endsWith(ext));
  const isDiskImage = magic?.type === 'disk_image' ||
    ['.dd', '.img', '.e01', '.raw', '.dmg', '.vmdk', '.vdi', '.qcow2'].some(ext => fileName.endsWith(ext)) ||
    fileCommand.toLowerCase().includes('partition') || fileCommand.toLowerCase().includes('filesystem') ||
    fileCommand.toLowerCase().includes('boot sector') || fileCommand.toLowerCase().includes('disk image');
  const isEncrypted = entropyLevel === 'very_high' && !isCompressed;

  const suspiciousReasons = [];
  if (isEncrypted) suspiciousReasons.push('Very high entropy — possible encrypted or packed content');
  if (isExecutable && entropy > 7) suspiciousReasons.push('Executable with high entropy — possibly packed/obfuscated');
  if (fileName.startsWith('.') && !isImage) suspiciousReasons.push('Hidden file (starts with dot)');
  if (fileName.includes('password') || fileName.includes('credential')) suspiciousReasons.push('Filename contains sensitive keywords');
  if (fileName.includes('keylogger') || fileName.includes('rootkit')) suspiciousReasons.push('Filename matches known malware patterns');
  if (fileName.includes('inject') || fileName.includes('hook')) suspiciousReasons.push('Filename suggests code injection');
  if (isExecutable && !isCompressed && entropy > 7.5) suspiciousReasons.push('Possibly packed with UPX or similar');
  if (entropyLevel === 'very_high' && fileStat.size < 100000) suspiciousReasons.push('Small file with very high entropy — potential encrypted payload');
  if (magic?.type === 'executable' && fileCommand.includes('script')) suspiciousReasons.push('Executable script detected');
  if (isDiskImage && fileStat.size > 10 * 1024 * 1024 * 1024) suspiciousReasons.push('Very large disk image — verify acquisition integrity');

  let diskImageInfo = undefined;
  if (isDiskImage) {
    try { diskImageInfo = analyzeDiskImage(filePath) || undefined; } catch (err) { console.warn(`[WORKER] Disk image analysis: ${err.message}`); }
  }

  return {
    filePath, fileName: basename(filePath), fileSize: fileStat.size,
    magicType: magic?.type || 'unknown', magicDescription: magic?.description || 'Unknown format',
    mimeType: fileCommand, entropy: Math.round(entropy * 1000) / 1000, entropyLevel,
    isEncrypted, isExecutable, isCompressed, isImage, isDocument, isDiskImage,
    isSuspicious: suspiciousReasons.length > 0, suspiciousReasons, fileCommand, stringsCount, diskImageInfo,
  };
}

// ═══════════════════════════════════════════════════════════════════════════════
// STRING EXTRACTION
// ═══════════════════════════════════════════════════════════════════════════════

function extractStrings(filePath, minLength = 4) {
  try {
    if (!existsSync(filePath)) return [];
    const output = safeRun(`strings -n ${minLength} "${filePath}"`, { ...LONG_EXEC_OPTS, maxBuffer: 200 * 1024 * 1024, timeout: 60000 });
    if (!output) return [];
    const lines = output.split('\n').filter(s => s.trim().length > 0);
    return lines.length > 100000 ? lines.slice(0, 100000) : lines;
  } catch {
    return [];
  }
}

function searchStringsForKeywords(strings, keywords) {
  return keywords.map(keyword => {
    const lowerKeyword = keyword.toLowerCase();
    const matches = strings.map((s, i) => ({ string: s, index: i })).filter(m => m.string.toLowerCase().includes(lowerKeyword));
    return { keyword, matches: matches.slice(0, 100), totalMatches: matches.length };
  }).filter(r => r.totalMatches > 0);
}

// ═══════════════════════════════════════════════════════════════════════════════
// KEYWORD SEARCH
// ═══════════════════════════════════════════════════════════════════════════════

function searchKeywordsInContent(content, fileName, keywords) {
  const searchKeywords = keywords || FORENSIC_KEYWORDS;
  const lines = content.split('\n');
  const results = [];
  for (const keyword of searchKeywords) {
    const matches = [];
    const lowerKeyword = keyword.toLowerCase();
    lines.forEach((line, idx) => {
      if (line.toLowerCase().includes(lowerKeyword)) {
        matches.push({ file: fileName, line: idx + 1, context: line.trim().substring(0, 300), source: fileName });
      }
    });
    if (matches.length > 0) results.push({ keyword, matches: matches.slice(0, 100), totalMatches: matches.length });
  }
  return results.sort((a, b) => b.totalMatches - a.totalMatches);
}

// ═══════════════════════════════════════════════════════════════════════════════
// LOG PARSING
// ═══════════════════════════════════════════════════════════════════════════════

function parseTimestamp(line) {
  for (const { regex } of LOG_TIMESTAMP_PATTERNS) {
    const match = line.match(regex);
    if (match) {
      try {
        let ts = match[1];
        if (/\d{2}\/[A-Za-z]{3}\/\d{4}/.test(ts)) {
          const d = new Date(ts.replace(/(\d{2})\/([A-Za-z]{3})\/(\d{4})/, '$2 $1, $3'));
          if (!isNaN(d.getTime())) return d;
        }
        if (!ts.includes('T') && !ts.includes('Z') && /^\d{4}-\d{2}-\d{2}\s/.test(ts)) ts = ts.replace(' ', 'T');
        const d = new Date(ts);
        if (!isNaN(d.getTime())) return d;
      } catch { /* continue */ }
    }
  }
  return null;
}

function classifyLogLine(line) {
  for (const kw of LOG_SUSPICIOUS_KEYWORDS) {
    if (kw.pattern.test(line)) {
      const confidence = kw.severity === 'critical' ? 0.9 : kw.severity === 'highly_suspicious' ? 0.8 : 0.7;
      return { action: kw.action, severity: kw.severity, confidence };
    }
  }
  return { action: 'unknown', severity: 'benign', confidence: 0.5 };
}

function parseLogFile(content, sourceName) {
  const lines = content.split('\n');
  const events = [];
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.length < 5) continue;
    const timestamp = parseTimestamp(trimmed);
    const { action, severity, confidence } = classifyLogLine(trimmed);
    let entity = 'unknown';
    const ipMatch = trimmed.match(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/);
    const fileMatch = trimmed.match(/(?:\/[\w.\-]+){2,}/);
    const userMatch = trimmed.match(/(?:user[=:\s]+)(\w+)/i);
    if (ipMatch) entity = ipMatch[1];
    else if (fileMatch) entity = fileMatch[0].substring(0, 80);
    else if (userMatch) entity = userMatch[1];
    else {
      const stripped = trimmed.replace(/[\[\]<>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z:+\s]+/, '');
      const words = stripped.split(/\s+/);
      entity = words.slice(0, 3).join(' ').substring(0, 80);
    }
    events.push({
      timestamp: timestamp || new Date(), action, entity: entity.substring(0, 100),
      description: trimmed.substring(0, 500), source: sourceName, severity, confidence, raw: trimmed,
    });
  }
  return events;
}

// ═══════════════════════════════════════════════════════════════════════════════
// TEXT FILE HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

function isTextFile(content) {
  let printable = 0;
  const sample = content.substring(0, 10000);
  for (let i = 0; i < sample.length; i++) {
    const code = sample.charCodeAt(i);
    if (code === 10 || code === 13 || code === 9 || (code >= 32 && code <= 126) || code >= 128) printable++;
  }
  return sample.length > 0 && printable / sample.length > 0.85;
}

function safeReadText(filePath) {
  try {
    const stat = statSync(filePath);
    if (stat.size === 0) return '';
    const toRead = Math.min(MAX_TEXT_READ, stat.size);
    const buf = Buffer.alloc(toRead);
    const fd = openSync(filePath, 'r');
    try { readSync(fd, buf, 0, toRead, 0); } finally { closeSync(fd); }
    return buf.toString('utf-8');
  } catch { return ''; }
}

// ═══════════════════════════════════════════════════════════════════════════════
// IMAGE ANALYSIS — CLI ONLY (exiftool + identify, NO sharp/exifr)
// ═══════════════════════════════════════════════════════════════════════════════

async function analyzeImage(filePath) {
  try {
    if (!existsSync(filePath)) return null;
    const fileName = basename(filePath);

    // 1. Get image dimensions using `identify` (ImageMagick) or `file` command
    let format = 'unknown';
    let width = 0;
    let height = 0;
    let channels = 3;
    let hasAlpha = false;
    let density = undefined;

    const identifyOutput = safeRun(`identify -verbose "${filePath}" 2>/dev/null | head -30`);
    if (identifyOutput) {
      const geomMatch = identifyOutput.match(/(\d+)x(\d+)/);
      if (geomMatch) { width = parseInt(geomMatch[1], 10); height = parseInt(geomMatch[2], 10); }
      const fmtMatch = identifyOutput.match(/^(\w+)\s/i);
      if (fmtMatch) format = fmtMatch[1].toUpperCase();
      if (identifyOutput.includes('Alpha:') || identifyOutput.includes('RGBA')) { channels = 4; hasAlpha = true; }
      const densityMatch = identifyOutput.match(/Resolution:\s*(\d+)/i);
      if (densityMatch) density = parseInt(densityMatch[1], 10);
      if (identifyOutput.includes('Gray') || identifyOutput.includes('Grayscale')) channels = 1;
      if (identifyOutput.includes('CMYK')) channels = 4;
    }

    if (width === 0) {
      const fileOutput = safeRun(`file "${filePath}"`);
      if (fileOutput) {
        const geomMatch = fileOutput.match(/(\d+)\s*x\s*(\d+)/);
        if (geomMatch) { width = parseInt(geomMatch[1], 10); height = parseInt(geomMatch[2], 10); }
        const fmtMatch = fileOutput.match(/(JPEG|PNG|GIF|BMP|WebP|TIFF|SVG)/i);
        if (fmtMatch) format = fmtMatch[1].toUpperCase();
      }
    }

    // 2. Get full EXIF data using exiftool
    let exifRecord = null;
    let gpsRecord = null;

    const exiftoolOutput = safeRun(`exiftool -j -G "${filePath}" 2>/dev/null`);
    if (exiftoolOutput) {
      try {
        const parsed = JSON.parse(exiftoolOutput);
        exifRecord = (Array.isArray(parsed) && parsed.length > 0) ? parsed[0] : (typeof parsed === 'object' ? parsed : null);
      } catch { /* ignore */ }
    }

    if (exifRecord) {
      const gpsLat = exifRecord['GPS:GPSLatitude'] || exifRecord['GPSLatitude'];
      const gpsLon = exifRecord['GPS:GPSLongitude'] || exifRecord['GPSLongitude'];
      if (gpsLat && gpsLon) {
        const lat = typeof gpsLat === 'number' ? gpsLat : parseFloat(String(gpsLat));
        const lon = typeof gpsLon === 'number' ? gpsLon : parseFloat(String(gpsLon));
        if (!isNaN(lat) && !isNaN(lon)) gpsRecord = { latitude: lat, longitude: lon };
      }
    }

    // Flatten EXIF data
    const exifData = {};
    if (exifRecord) {
      for (const [key, value] of Object.entries(exifRecord)) {
        if (value !== null && value !== undefined) exifData[key] = typeof value === 'object' ? JSON.stringify(value) : String(value);
      }
    }

    const creationDate = exifRecord?.['EXIF:DateTimeOriginal'] || exifRecord?.['EXIF:DateTimeDigitized'] || exifRecord?.['EXIF:DateTime'] || exifRecord?.['EXIF:CreateDate'] || null;
    const cameraMake = exifRecord?.['EXIF:Make'] || exifRecord?.['Make'] || null;
    const cameraModel = exifRecord?.['EXIF:Model'] || exifRecord?.['Model'] || null;
    const software = exifRecord?.['EXIF:Software'] || exifRecord?.['Software'] || null;

    const suspiciousReasons = [];
    if (gpsRecord) suspiciousReasons.push(`GPS coordinates found: ${gpsRecord.latitude}, ${gpsRecord.longitude}`);
    if (software && /photoshop|gimp|paint/i.test(String(software))) suspiciousReasons.push(`Image edited with: ${String(software)}`);
    if (!creationDate && !cameraMake && Object.keys(exifData).length === 0) suspiciousReasons.push('No EXIF data — image may have been stripped');
    if (hasAlpha) suspiciousReasons.push('RGBA image with alpha channel — potential steganography vector');

    return {
      fileName, format, width, height, channels, hasAlpha, density,
      exifData, gpsData: gpsRecord, hasGPS: !!gpsRecord,
      creationDate: creationDate ? String(creationDate) : null,
      cameraMake: cameraMake ? String(cameraMake) : null,
      cameraModel: cameraModel ? String(cameraModel) : null,
      software: software ? String(software) : null,
      isSuspicious: suspiciousReasons.length > 0, suspiciousReasons,
    };
  } catch (error) {
    console.error(`[WORKER] Image analysis failed:`, error.message);
    return null;
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// SQLITE DATABASE PARSING — CLI ONLY (sqlite3 command, NO better-sqlite3)
// ═══════════════════════════════════════════════════════════════════════════════

function safeSqlite3(sql, dbPath) {
  try {
    return execSync(`sqlite3 "${dbPath}" "${sql}"`, {
      encoding: 'utf-8', maxBuffer: 50 * 1024 * 1024, timeout: 30000,
    }).trim();
  } catch {
    return null;
  }
}

async function parseSqliteDatabase(filePath) {
  const empty = { databaseType: 'unknown', tables: [], history: [], downloads: [], bookmarks: [], rowCount: {}, suspiciousUrls: [] };
  try {
    if (!existsSync(filePath)) return empty;

    // Check if sqlite3 CLI is available
    if (!safeRun('which sqlite3')) {
      console.warn('[WORKER] sqlite3 CLI not found — SQLite analysis disabled');
      return empty;
    }

    const tablesOutput = safeSqlite3("SELECT name FROM sqlite_master WHERE type='table';", filePath);
    if (!tablesOutput) return empty;

    const tables = tablesOutput.split('\n').map(t => t.trim()).filter(Boolean);
    const dbType = (() => {
      if (tables.includes('urls') && tables.includes('visits')) return 'chrome_history';
      if (tables.includes('moz_places') && tables.includes('moz_historyvisits')) return 'firefox_history';
      if (tables.includes('downloads')) return 'chrome_downloads';
      if (tables.length > 0) return 'generic';
      return 'unknown';
    })();

    const rowCount = {};
    for (const table of tables) {
      const countOutput = safeSqlite3(`SELECT COUNT(*) FROM "${table}";`, filePath);
      rowCount[table] = countOutput ? parseInt(countOutput, 10) : -1;
    }

    const history = [], downloads = [], suspiciousUrls = [];

    if (dbType === 'chrome_history') {
      const historyOutput = safeSqlite3(
        `SELECT url, title, visit_count, typed_count,
           datetime(last_visit_time / 1000000 - 11644473600, 'unixepoch') as last_visit
         FROM urls ORDER BY last_visit_time DESC LIMIT 500;`, filePath
      );
      if (historyOutput) {
        for (const line of historyOutput.split('\n')) {
          const parts = line.split('|');
          if (parts.length >= 4) {
            const url = parts[0] || '';
            const title = parts[1] || '';
            history.push({ url, title, visitCount: parseInt(parts[2], 10) || 0, lastVisitTime: parts[4] || '', typedCount: parseInt(parts[3], 10) || 0 });
            for (const sp of SUSPICIOUS_URL_PATTERNS) {
              if (sp.pattern.test(url) || sp.pattern.test(title)) { suspiciousUrls.push({ url, title, reason: sp.reason }); break; }
            }
          }
        }
      }

      const dlOutput = safeSqlite3(
        `SELECT url, target_path, received_bytes, total_bytes,
           datetime(start_time / 1000000 - 11644473600, 'unixepoch') as start_time, mime_type
         FROM downloads ORDER BY start_time DESC LIMIT 200;`, filePath
      );
      if (dlOutput) {
        for (const line of dlOutput.split('\n')) {
          const parts = line.split('|');
          if (parts.length >= 5) {
            downloads.push({ url: parts[0] || '', targetPath: parts[1] || '', startTime: parts[4] || '', receivedBytes: parseInt(parts[2], 10) || 0, totalBytes: parseInt(parts[3], 10) || 0, mimeType: parts[5] || '' });
          }
        }
      }
    }

    if (dbType === 'firefox_history') {
      const historyOutput = safeSqlite3(
        `SELECT url, title, visit_count,
           datetime(last_visit_date / 1000000, 'unixepoch') as last_visit
         FROM moz_places ORDER BY last_visit_date DESC LIMIT 500;`, filePath
      );
      if (historyOutput) {
        for (const line of historyOutput.split('\n')) {
          const parts = line.split('|');
          if (parts.length >= 3) {
            const url = parts[0] || '';
            const title = parts[1] || '';
            history.push({ url, title, visitCount: parseInt(parts[2], 10) || 0, lastVisitTime: parts[3] || '', typedCount: 0 });
            for (const sp of SUSPICIOUS_URL_PATTERNS) {
              if (sp.pattern.test(url) || sp.pattern.test(title)) { suspiciousUrls.push({ url, title, reason: sp.reason }); break; }
            }
          }
        }
      }
    }

    return { databaseType: dbType, tables, history, downloads, bookmarks: [], rowCount, suspiciousUrls };
  } catch (error) {
    console.error(`[WORKER] SQLite parse failed:`, error.message);
    return empty;
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// TOOL WRAPPERS (CLI-based forensic tools)
// ═══════════════════════════════════════════════════════════════════════════════

// --- Sleuth Kit (disk image analysis) ---
function analyzeWithSleuthKit(filePath) {
  const result = { partitions: [], fileSystemEntries: [], deletedFiles: [], timelineEvents: [] };
  try {
    const mmlsOutput = safeRun(`mmls "${filePath}" 2>/dev/null`);
    if (mmlsOutput) {
      for (const line of mmlsOutput.split('\n').filter(l => l.trim() && !l.startsWith('DOS') && !l.includes('Units'))) {
        const parts = line.trim().split(/\s+/);
        if (parts.length >= 5 && /^\d+:/.test(parts[0])) {
          result.partitions.push({ start: parts[1], end: parts[2], description: parts.slice(5).join(' ') || parts[4], type: parts[4] || '' });
        }
      }
    }
  } catch { /* ignore */ }
  try {
    const flsOutput = safeRun(`fls -r -p -l -u "${filePath}" 2>/dev/null | head -300`, LONG_EXEC_OPTS);
    if (flsOutput) {
      for (const line of flsOutput.split('\n').filter(l => l.trim()).slice(0, 200)) {
        const metaMatch = line.match(/^\s*(\d+)\s+/);
        const isDeleted = line.includes('(Deleted)') || line.includes('* ');
        const nameParts = line.trim().split(/\s+/);
        const name = nameParts[nameParts.length - 1] || 'unknown';
        result.fileSystemEntries.push({
          name, isDeleted, isDirectory: line.includes('d/'),
          size: '0', inode: metaMatch?.[1] || '',
          filePath: name, modifiedTime: new Date().toISOString(),
        });
      }
      result.deletedFiles = result.fileSystemEntries.filter(e => e.isDeleted);
    }
  } catch { /* ignore */ }
  return result;
}

// --- Volatility3 (memory dump analysis) ---
function analyzeMemoryDump(filePath) {
  const result = { osInfo: null, processes: [], hiddenProcesses: [], networkConnections: [], commandLines: [], suspiciousFindings: [] };
  try {
    const infoOutput = safeRun(`vol -f "${filePath}" windows.info.Info 2>/dev/null || vol.py -f "${filePath}" windows.info.Info 2>/dev/null`, { ...LONG_EXEC_OPTS, timeout: 120000 });
    if (infoOutput) {
      const osMatch = infoOutput.match(/OS:\s*(.+)/i);
      if (osMatch) result.osInfo = { osName: osMatch[1].trim(), osVersion: '', architecture: '', kernelVersion: '', dtbAddress: '', createdAt: new Date().toISOString() };
    }
  } catch { /* ignore */ }
  try {
    const psOutput = safeRun(`vol -f "${filePath}" windows.pslist.PsList --output=csv 2>/dev/null | head -200`, { ...LONG_EXEC_OPTS, timeout: 120000 });
    if (psOutput) {
      const lines = psOutput.split('\n').filter(l => l.trim());
      if (lines.length > 1) {
        const headers = lines[0].split(',').map(h => h.trim().replace(/"/g, ''));
        for (const line of lines.slice(1)) {
          const vals = line.split(',').map(v => v.trim().replace(/"/g, ''));
          const row = {};
          headers.forEach((h, i) => row[h] = vals[i] || '');
          const pid = parseInt(row.PID || row.pid || '0');
          if (pid > 0) result.processes.push({ pid, ppid: parseInt(row.PPID || row.ppid || '0'), name: row.Name || row.name || row.ImageFileName || '', commandLine: row['Command Line'] || row.CommandLine || '', createTime: row.CreateTime || '', exitTime: '', threads: parseInt(row.Threads || '0'), handles: parseInt(row.Handles || '0'), sessionId: '', wow64: false, source: 'pslist', isHidden: false });
        }
      }
    }
  } catch { /* ignore */ }
  try {
    const psscanOutput = safeRun(`vol -f "${filePath}" windows.psscan.PsScan --output=csv 2>/dev/null | head -200`, { ...LONG_EXEC_OPTS, timeout: 120000 });
    if (psscanOutput && result.processes.length > 0) {
      const psscanPids = new Set();
      const lines = psscanOutput.split('\n').filter(l => l.trim());
      if (lines.length > 1) {
        const headers = lines[0].split(',').map(h => h.trim().replace(/"/g, ''));
        for (const line of lines.slice(1)) {
          const vals = line.split(',').map(v => v.trim().replace(/"/g, ''));
          const row = {};
          headers.forEach((h, i) => row[h] = vals[i] || '');
          const pid = parseInt(row.PID || row.pid || '0');
          psscanPids.add(pid);
        }
      }
      const pslistPids = new Set(result.processes.map(p => p.pid));
      for (const pid of psscanPids) {
        if (!pslistPids.has(pid)) result.hiddenProcesses.push({ pid, ppid: 0, name: 'hidden', commandLine: '', source: 'psscan', isHidden: true });
      }
    }
  } catch { /* ignore */ }
  try {
    const netOutput = safeRun(`vol -f "${filePath}" windows.netstat.NetStat --output=csv 2>/dev/null | head -200`, { ...LONG_EXEC_OPTS, timeout: 120000 });
    if (netOutput) {
      const lines = netOutput.split('\n').filter(l => l.trim());
      if (lines.length > 1) {
        const headers = lines[0].split(',').map(h => h.trim().replace(/"/g, ''));
        for (const line of lines.slice(1).slice(0, 50)) {
          const vals = line.split(',').map(v => v.trim().replace(/"/g, ''));
          const row = {};
          headers.forEach((h, i) => row[h] = vals[i] || '');
          const addrMatch = (row['LocalAddr'] || row['Remote Address'] || '').match(/(.+):(\d+)/);
          const raddrMatch = (row['ForeignAddr'] || row['Foreign Address'] || '').match(/(.+):(\d+)/);
          result.networkConnections.push({
            pid: parseInt(row.PID || row.pid || '0'), processName: row['Process'] || row.ImageFileName || '',
            protocol: row.Proto || '', localAddress: addrMatch?.[1] || '', localPort: parseInt(addrMatch?.[2] || '0'),
            remoteAddress: raddrMatch?.[1] || '', remotePort: parseInt(raddrMatch?.[2] || '0'), state: row.State || '',
          });
        }
      }
    }
  } catch { /* ignore */ }

  const susProcs = result.processes.filter(p => /password|credential|inject|hook|keylog|rootkit/i.test(p.commandLine || ''));
  for (const sp of susProcs) {
    result.suspiciousFindings.push({ category: 'Memory Analysis', severity: 'critical', title: `Suspicious process: ${sp.name} (PID ${sp.pid})`, description: `Command: ${sp.commandLine || 'N/A'}`, evidence: basename(filePath) });
  }
  if (result.hiddenProcesses.length > 0) {
    result.suspiciousFindings.push({ category: 'Memory Analysis', severity: 'critical', title: `${result.hiddenProcesses.length} hidden processes found`, description: `Possible rootkit: ${result.hiddenProcesses.slice(0, 10).map(p => `${p.name}(${p.pid})`).join(', ')}`, evidence: basename(filePath) });
  }
  return result;
}

// --- TShark (PCAP analysis) ---
function analyzePCAP(filePath) {
  const result = { totalPackets: 0, dnsQueries: [], httpRequests: [], tcpConnections: [], tlsHandshakes: [], credentials: [], suspiciousFindings: [] };

  try {
    const pcapInfo = safeRun(`tshark -r "${filePath}" -q -z io,phs 2>/dev/null | head -5`);
    const pktMatch = pcapInfo?.match(/(\d+)\s+packets/i);
    result.totalPackets = pktMatch ? parseInt(pktMatch[1], 10) : 0;
  } catch { /* ignore */ }

  try {
    const dnsOutput = safeRun(`tshark -r "${filePath}" -Y "dns.qry.name" -T fields -e dns.qry.name -e dns.a -E header=n -E separator="|" 2>/dev/null | head -200`, { ...LONG_EXEC_OPTS, timeout: 60000 });
    if (dnsOutput) {
      for (const line of dnsOutput.split('\n').filter(l => l.trim())) {
        const [domain, ip] = [line.split('|')[0]?.trim(), line.split('|')[1]?.trim()];
        if (domain) result.dnsQueries.push({ domain, resolvedIp: ip || '', timestamp: '' });
      }
    }
  } catch { /* ignore */ }

  try {
    const httpOutput = safeRun(`tshark -r "${filePath}" -Y "http.request" -T fields -e http.host -e http.request.uri -e http.request.method -E header=n -E separator="|" 2>/dev/null | head -200`, { ...LONG_EXEC_OPTS, timeout: 60000 });
    if (httpOutput) {
      for (const line of httpOutput.split('\n').filter(l => l.trim())) {
        const [host, uri, method] = line.split('|').map(s => s?.trim());
        if (host) result.httpRequests.push({ host, uri: uri || '/', method: method || 'GET' });
      }
    }
  } catch { /* ignore */ }

  try {
    const tcpOutput = safeRun(`tshark -r "${filePath}" -Y "tcp.flags.syn==1" -T fields -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -E header=n -E separator="|" 2>/dev/null | head -200`, { ...LONG_EXEC_OPTS, timeout: 60000 });
    if (tcpOutput) {
      for (const line of tcpOutput.split('\n').filter(l => l.trim())) {
        const [srcIp, dstIp, srcPort, dstPort] = line.split('|').map(s => s?.trim());
        if (srcIp) result.tcpConnections.push({ srcIp, dstIp: dstIp || '', srcPort: parseInt(srcPort) || 0, dstPort: parseInt(dstPort) || 0 });
      }
    }
  } catch { /* ignore */ }

  try {
    const credOutput = safeRun(`tshark -r "${filePath}" -Y "ftp.request.command==PASS or (http.request.method==POST and http.authorization) or (smtp.req.command==AUTH)" -T fields -e frame.protocols -e ip.src -e ip.dst -e ftp.request.arg -E header=n -E separator="|" 2>/dev/null | head -50`, { ...LONG_EXEC_OPTS, timeout: 60000 });
    if (credOutput) {
      for (const line of credOutput.split('\n').filter(l => l.trim())) {
        const [proto, src, dst, info] = line.split('|').map(s => s?.trim());
        if (proto) result.credentials.push({ protocol: proto?.split(':')[0] || 'unknown', srcIp: src || '', dstIp: dst || '', username: '', password: info || '', info: info || '' });
      }
    }
  } catch { /* ignore */ }

  // Check for suspicious patterns
  if (result.dnsQueries.some(d => /\.onion/i.test(d.domain))) {
    result.suspiciousFindings.push({ category: 'Network Analysis', severity: 'critical', title: 'Tor .onion domain accessed', description: result.dnsQueries.filter(d => /\.onion/i.test(d.domain)).map(d => d.domain).join(', '), evidence: basename(filePath) });
  }
  if (result.credentials.length > 0) {
    result.suspiciousFindings.push({ category: 'Network Analysis', severity: 'critical', title: `${result.credentials.length} credential(s) captured`, description: result.credentials.map(c => `${c.protocol}: ${c.info}`).join('\n'), evidence: basename(filePath) });
  }
  return result;
}

// --- Archive extraction ---
function extractAndAnalyzeArchive(filePath, extractDir) {
  const result = { extractedFiles: [], suspiciousFindings: [] };
  ensureDir(extractDir);
  try {
    safeRun(`7z x -y -o"${extractDir}" "${filePath}" 2>/dev/null || unzip -o -d "${extractDir}" "${filePath}" 2>/dev/null || tar xf "${filePath}" -C "${extractDir}" 2>/dev/null`, LONG_EXEC_OPTS);
    const extracted = readdirSync(extractDir);
    for (const name of extracted.slice(0, 500)) {
      const ep = join(extractDir, name);
      try {
        const stat = statSync(ep);
        const isSusp = name.match(/password|credential|key|secret|hack|exploit|malware/i) !== null;
        result.extractedFiles.push({ name, path: ep, size: stat.size, isDirectory: stat.isDirectory(), suspicious: isSusp, hash: '' });
      } catch { /* ignore */ }
    }
  } catch { /* ignore */ }
  return result;
}

// --- Registry hive analysis (hivex) ---
function analyzeRegistryHive(filePath) {
  const result = { runKeys: [], usbDevices: [], installedSoftware: [], userAccounts: [], suspiciousFindings: [] };
  try {
    const regOutput = safeRun(`hivexregedit --export "${filePath}" 2>/dev/null | head -500`, LONG_EXEC_OPTS);
    if (regOutput) {
      const runKeyMatch = regOutput.match(/\[.*?(Run|RunOnce|Winlogon|Shell|Userinit|Load).*?\][\s\S]*?("(?:.|\n)*?")\s*=/gi);
      if (runKeyMatch) {
        for (const block of runKeyMatch.slice(0, 20)) {
          const keyMatch = block.match(/\[([^\]]+)\]/);
          const valMatch = block.match(/"([^"]*)"\s*=\s*"?([^"\n]*)"?/);
          if (keyMatch && valMatch) result.runKeys.push({ key: keyMatch[1], value: valMatch[2] || valMatch[1] || '' });
        }
      }
      const usbMatch = regOutput.match(/USBSTOR#\{[^\}]+\}/gi);
      if (usbMatch) {
        for (const usb of usbMatch.slice(0, 20)) {
          result.usbDevices.push({ deviceName: usb.replace(/"/g, ''), serial: '', lastWriteTime: new Date().toISOString() });
        }
      }
    }
  } catch { /* ignore */ }
  if (result.runKeys.length > 0) {
    result.suspiciousFindings.push({ category: 'Registry Analysis', severity: 'highly_suspicious', title: `${result.runKeys.length} Run keys detected (persistence)`, description: result.runKeys.map(r => `${r.key}: ${r.value}`).join('\n'), evidence: basename(filePath) });
  }
  return result;
}

// --- PDF analysis ---
function analyzePDF(filePath) {
  const result = { hasJS: false, hasActions: false, hasEmbeddedFiles: false, pages: 0, metadata: {}, suspiciousFindings: [] };
  try {
    const pdfOutput = safeRun(`exiftool "${filePath}" 2>/dev/null`);
    if (pdfOutput) {
      const lines = pdfOutput.split('\n');
      for (const line of lines) {
        if (/JavaScript/i.test(line)) result.hasJS = true;
        if (/OpenAction|Launch|GoTo|URI/i.test(line)) result.hasActions = true;
        if (/Embedded\s*File|EmbeddedCount/i.test(line)) result.hasEmbeddedFiles = true;
        if (/Page\s*Count/i.test(line)) result.pages = parseInt(line.match(/(\d+)/)?.[1] || '0', 10);
        const kvMatch = line.match(/^([^:]+):\s*(.+)/);
        if (kvMatch) result.metadata[kvMatch[1].trim()] = kvMatch[2].trim();
      }
    }
  } catch { /* ignore */ }
  return result;
}

// --- ExifTool analysis ---
function analyzeWithExifTool(filePath) {
  const result = { metadata: {}, gpsCoordinates: null, cameraInfo: null, suspiciousFindings: [] };
  try {
    const output = safeRun(`exiftool "${filePath}" 2>/dev/null`);
    if (output) {
      for (const line of output.split('\n')) {
        const kvMatch = line.match(/^([^:]+):\s*(.+)/);
        if (kvMatch) result.metadata[kvMatch[1].trim()] = kvMatch[2].trim();
      }
      const make = result.metadata['Make'] || '';
      const model = result.metadata['Model'] || '';
      if (make || model) result.cameraInfo = { make, model };

      const lat = result.metadata['GPS Latitude'];
      const lon = result.metadata['GPS Longitude'];
      if (lat && lon) {
        const latNum = parseFloat(lat);
        const lonNum = parseFloat(lon);
        if (!isNaN(latNum) && !isNaN(lonNum)) result.gpsCoordinates = { latitude: latNum, longitude: lonNum };
      }
    }
  } catch { /* ignore */ }
  return result;
}

// --- Binwalk analysis ---
function analyzeWithBinwalk(filePath) {
  const result = { embeddedFiles: [], suspiciousFindings: [] };
  try {
    const output = safeRun(`binwalk "${filePath}" 2>/dev/null`, { ...LONG_EXEC_OPTS, timeout: 120000 });
    if (output) {
      for (const line of output.split('\n')) {
        const match = line.match(/^(\d+)\s+(.+)$/);
        if (match) result.embeddedFiles.push({ offset: parseInt(match[1], 10), description: match[2].trim() });
      }
    }
  } catch { /* ignore */ }
  return result;
}

// ═══════════════════════════════════════════════════════════════════════════════
// IOC EXTRACTION — Extract Indicators of Compromise from all evidence
// ═══════════════════════════════════════════════════════════════════════════════

function extractIOCsFromText(text, source) {
  const iocs = [];
  const seen = new Set();
  
  function addIOC(type, value, context, severity, tags = []) {
    const key = `${type}:${value}`;
    if (seen.has(key)) return;
    seen.add(key);
    iocs.push({ type, value, source, context: context.substring(0, 200), severity, firstSeen: new Date().toISOString(), tags });
  }

  // IP addresses (v4)
  const ipRegex = /\b((?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?))\b/g;
  let match;
  while ((match = ipRegex.exec(text)) !== null) {
    const ip = match[1];
    if (ip === '0.0.0.0' || ip === '127.0.0.1' || ip === '255.255.255.255') continue;
    const start = Math.max(0, match.index - 50);
    const end = Math.min(text.length, match.index + ip.length + 50);
    const ctx = text.substring(start, end).replace(/\s+/g, ' ').trim();
    const sev = /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip) ? 'low' : 
                /\.(onion|tor|darknet)\b/i.test(ctx) ? 'critical' : 'medium';
    addIOC('ip', ip, ctx, sev);
  }

  // URLs
  const urlRegex = /\b(https?:\/\/[^\s"'<>\]\)]+)/gi;
  while ((match = urlRegex.exec(text)) !== null) {
    const url = match[1];
    const start = Math.max(0, match.index - 30);
    const ctx = text.substring(start, Math.min(text.length, match.index + url.length + 30)).replace(/\s+/g, ' ').trim();
    const sev = /\.onion/i.test(url) ? 'critical' : 
                /darknet|malware|exploit|hack|phishing/i.test(url) ? 'high' : 'medium';
    const tags = [];
    if (/\.onion/i.test(url)) tags.push('tor');
    if (/\.exe|\.dll|\.ps1|\.bat|\.scr/i.test(url)) tags.push('executable-download');
    if (/password|credential|leak|dump/i.test(url)) tags.push('credential-leak');
    addIOC('url', url, ctx, sev, tags);
  }

  // Domains
  const domainRegex = /\b((?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:onion|com|net|org|io|ru|cn|de|uk|fr|br|in|info|biz|xyz|top|tk|ml|ga|cf|gq))\b/g;
  while ((match = domainRegex.exec(text)) !== null) {
    const domain = match[1].toLowerCase();
    if (seen.has(`domain:${domain}`)) continue;
    const start = Math.max(0, match.index - 40);
    const ctx = text.substring(start, Math.min(text.length, match.index + domain.length + 40)).replace(/\s+/g, ' ').trim();
    const sev = domain.endsWith('.onion') ? 'critical' : 
                /malware|exploit|phishing|darknet/i.test(ctx) ? 'high' : 'low';
    addIOC('domain', domain, ctx, sev);
  }

  // Email addresses
  const emailRegex = /\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b/g;
  while ((match = emailRegex.exec(text)) !== null) {
    const email = match[1].toLowerCase();
    const start = Math.max(0, match.index - 30);
    const ctx = text.substring(start, Math.min(text.length, match.index + email.length + 30)).replace(/\s+/g, ' ').trim();
    const sev = /admin|root|hack|malware|spam/i.test(email) ? 'high' : 'medium';
    addIOC('email', email, ctx, sev);
  }

  // Bitcoin/crypto wallets
  const btcRegex = /\b([13][a-km-zA-HJ-NP-Z1-9]{25,34})\b/g;
  while ((match = btcRegex.exec(text)) !== null) {
    const wallet = match[1];
    const start = Math.max(0, match.index - 30);
    const ctx = text.substring(start, Math.min(text.length, match.index + wallet.length + 30)).replace(/\s+/g, ' ').trim();
    addIOC('bitcoin', wallet, ctx, 'high', ['cryptocurrency']);
  }
  const xmrRegex = /\b(4[0-9AB][1-9A-HJ-NP-Za-km-z]{93})\b/g;
  while ((match = xmrRegex.exec(text)) !== null) {
    addIOC('bitcoin', match[1].substring(0, 20) + '...', text.substring(Math.max(0, match.index - 30), match.index + 50).replace(/\s+/g, ' ').trim(), 'high', ['monero']);
  }

  // MAC addresses
  const macRegex = /\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\b/g;
  while ((match = macRegex.exec(text)) !== null) {
    const mac = match[0];
    if (seen.has(`mac:${mac}`)) continue;
    const start = Math.max(0, match.index - 30);
    const ctx = text.substring(start, Math.min(text.length, match.index + mac.length + 30)).replace(/\s+/g, ' ').trim();
    addIOC('mac', mac, ctx, 'low');
  }

  // CVE references
  const cveRegex = /\b(CVE-\d{4}-\d{4,})\b/g;
  while ((match = cveRegex.exec(text)) !== null) {
    const start = Math.max(0, match.index - 50);
    const ctx = text.substring(start, Math.min(text.length, match.index + match[0].length + 50)).replace(/\s+/g, ' ').trim();
    addIOC('cve', match[1], ctx, 'high', ['vulnerability']);
  }

  // File hashes (SHA-256, MD5 patterns)
  const hashRegex = /\b([a-fA-F0-9]{64})\b/g;
  while ((match = hashRegex.exec(text)) !== null) {
    const hash = match[1];
    if (seen.has(`hash:${hash}`)) continue;
    const start = Math.max(0, match.index - 30);
    const ctx = text.substring(start, Math.min(text.length, match.index + hash.length + 30)).replace(/\s+/g, ' ').trim();
    addIOC('hash', hash, ctx, 'medium', ['sha256']);
  }

  return iocs;
}

function extractIOCsFromAllEvidence(fileAnalyses, stringsResults, textContents) {
  const allIOCs = [];
  
  for (let i = 0; i < fileAnalyses.length; i++) {
    const fa = fileAnalyses[i];
    const source = fa.fileName || `file-${i}`;
    
    // Extract from strings
    if (stringsResults[i] && stringsResults[i].length > 0) {
      const text = stringsResults[i].join('\n');
      const iocs = extractIOCsFromText(text, source);
      allIOCs.push(...iocs);
    }

    // Extract from text content
    if (textContents[i]) {
      const iocs = extractIOCsFromText(textContents[i], source);
      allIOCs.push(...iocs);
    }
  }

  // Deduplicate by value (keep highest severity)
  const deduped = new Map();
  for (const ioc of allIOCs) {
    const existing = deduped.get(`${ioc.type}:${ioc.value}`);
    if (!existing) {
      deduped.set(`${ioc.type}:${ioc.value}`, ioc);
    } else {
      const sevOrder = { critical: 4, high: 3, medium: 2, low: 1 };
      if ((sevOrder[ioc.severity] || 0) > (sevOrder[existing.severity] || 0)) {
        deduped.set(`${ioc.type}:${ioc.value}`, { ...ioc, sources: [...(existing.sources || [existing.source]), ioc.source] });
      }
    }
  }

  return Array.from(deduped.values());
}

// ═══════════════════════════════════════════════════════════════════════════════
// MAIN ANALYSIS PIPELINE
// ═══════════════════════════════════════════════════════════════════════════════

async function main() {
  const caseDir = process.argv[2];
  if (!caseDir) {
    console.error('[WORKER] Usage: node scripts/analyze-worker.mjs <caseDir>');
    process.exit(1);
  }

  if (!existsSync(caseDir)) {
    console.error(`[WORKER] Case directory not found: ${caseDir}`);
    process.exit(1);
  }

  console.error(`[WORKER] Starting analysis for: ${caseDir}`);
  const startTime = Date.now();

  const fileNames = readdirSync(caseDir);
  if (fileNames.length === 0) {
    console.error('[WORKER] No files found in case directory');
    process.exit(1);
  }

  const processedFiles = [];
  const allTimelineEvents = [];
  const allFindings = [];
  const allKeywordResults = [];
  const allNodes = [];
  const allEdges = [];
  const allCustody = [];
  let eventId = 0;
  let findingId = 0;

  const caseInfo = {
    id: basename(caseDir),
    name: `Case ${basename(caseDir)}`,
    description: `Real forensic analysis of ${fileNames.length} evidence file(s)`,
    createdAt: new Date().toISOString(),
    status: 'active',
    evidenceIds: [],
    analyst: 'JURI-X Automated',
  };

  for (const fileName of fileNames) {
    const filePath = join(caseDir, fileName);

    try {
      const fileStat = statSync(filePath);
      console.error(`[WORKER] Processing: ${fileName} (${formatSize(fileStat.size)})`);

      // 1. Hash
      let hash = 'error';
      try { hash = await calculateFileHash(filePath); } catch (e) { console.warn(`[WORKER]   Hash failed: ${e.message}`); }

      allCustody.push({
        id: `cust-${allCustody.length + 1}`, evidenceId: fileName,
        action: 'uploaded', performedBy: 'JURI-X',
        timestamp: new Date().toISOString(),
        details: `File acquired: ${fileName} (${formatSize(fileStat.size)})`, hash,
      });

      // 2. File analysis
      let fileAnalysis;
      try {
        fileAnalysis = await analyzeFile(filePath);
      } catch (e) {
        console.warn(`[WORKER]   File analysis failed: ${e.message}`);
        fileAnalysis = {
          magicType: 'unknown', magicDescription: 'Analysis failed', entropy: 0, entropyLevel: 'low',
          isImage: false, isDiskImage: false, isExecutable: false, isCompressed: false, isEncrypted: false,
          isDocument: false, isSuspicious: false, suspiciousReasons: [],
          fileCommand: 'error', stringsCount: 0, diskImageInfo: null,
        };
      }

      const ext = extname(fileName).toLowerCase();
      const isSQLite = ['.db', '.sqlite', '.sqlite3'].some(e => ext === e) || fileAnalysis.magicType === 'database';
      const isImage = fileAnalysis.isImage || ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp'].some(e => ext === e);
      const isDiskImage = fileAnalysis.isDiskImage || ['.dd', '.img', '.e01', '.raw', '.dmg', '.vmdk', '.vdi', '.qcow2'].some(e => ext === e);

      // 3. Text content
      let fileContent = '';
      let isText = false;
      let isBinary = false;
      if (!isDiskImage && !isImage && !isSQLite) {
        fileContent = safeReadText(filePath);
        if (fileContent.length > 0) { isText = isTextFile(fileContent); isBinary = !isText; }
        else { isBinary = true; }
      } else { isBinary = true; }

      // 4. Strings
      let extractedStrings = [];
      if (isBinary || fileStat.size > 100_000) {
        console.error(`[WORKER]   Extracting strings...`);
        extractedStrings = extractStrings(filePath);
        console.error(`[WORKER]   Strings: ${extractedStrings.length}`);
      } else if (isText) {
        extractedStrings = fileContent.split('\n').filter(l => l.trim().length >= 4);
      }

      // 5. Keywords
      let keywordResults = [];
      if (isText && fileContent.length > 0) {
        keywordResults = searchKeywordsInContent(fileContent, fileName).filter(r => r.totalMatches > 0);
      } else if (extractedStrings.length > 0) {
        keywordResults = searchStringsForKeywords(extractedStrings, FORENSIC_KEYWORDS);
      }

      // 6. Log parsing
      let logEvents = [];
      if (isText && !isDiskImage && (ext === '.log' || ext === '.txt' || fileName.toLowerCase().includes('log') || fileName.toLowerCase().includes('event'))) {
        logEvents = parseLogFile(fileContent, fileName);
        console.error(`[WORKER]   Log events: ${logEvents.length}`);
      }

      // 7. Image analysis (exiftool CLI)
      let imageAnalysis = null;
      if (isImage) {
        try {
          imageAnalysis = await analyzeImage(filePath);
          if (imageAnalysis) console.error(`[WORKER]   Image: ${imageAnalysis.width}x${imageAnalysis.height}, GPS: ${imageAnalysis.hasGPS}`);
        } catch (e) { console.warn(`[WORKER]   Image analysis: ${e.message}`); }
      }

      // 8. SQLite parsing (sqlite3 CLI)
      let sqliteAnalysis = null;
      if (isSQLite) {
        try {
          sqliteAnalysis = await parseSqliteDatabase(filePath);
          console.error(`[WORKER]   SQLite: type=${sqliteAnalysis.databaseType}, tables=${sqliteAnalysis.tables.length}`);
        } catch (e) { console.warn(`[WORKER]   SQLite: ${e.message}`); }
      }

      // === DISK IMAGE ANALYSIS ===
      let diskImageInfo = fileAnalysis.diskImageInfo || null;
      if (isDiskImage) {
        console.error(`[WORKER]   === DISK IMAGE ===`);
        try {
          const skResult = analyzeWithSleuthKit(filePath);
          if (skResult.partitions?.length) {
            for (const part of skResult.partitions) {
              allNodes.push({ id: `sk-part-${part.start}-${fileName}`, type: 'artifact', label: part.description || `Partition ${part.start}`, properties: { start: part.start, end: part.end, type: part.type } });
            }
          }
          if (skResult.fileSystemEntries?.length) {
            for (const entry of skResult.fileSystemEntries.slice(0, 200)) {
              allTimelineEvents.push({
                id: `evt-sk-${++eventId}`, timestamp: entry.modifiedTime || new Date().toISOString(),
                action: (entry.name?.startsWith?.('Deleted') ? 'file_deleted' : entry.isDirectory ? 'file_opened' : 'file_modified'),
                entity: entry.name || 'unknown', description: entry.filePath || entry.name || '',
                source: `Sleuth Kit: ${fileName}`, confidence: 0.9, severity: 'benign', metadata: { size: entry.size }, relatedEvents: [],
              });
            }
          }
          if (skResult.deletedFiles?.length) {
            allFindings.push({ id: `find-sk-${++findingId}`, severity: 'suspicious', category: 'Disk Image (Sleuth Kit)', title: `Deleted files in ${fileName}`, description: `${skResult.deletedFiles.length} deleted file(s)`, evidence: fileName, timestamp: new Date().toISOString(), relatedArtifacts: [fileName], confidence: 0.95, recommendation: 'Use icat to recover.' });
          }
        } catch (e) { console.warn(`[WORKER]   Sleuth Kit: ${e.message}`); }
      }

      // === MEMORY DUMP ===
      const isMemDump = ['.dmp', '.vmem', '.liemem'].some(e => ext === e) && !isDiskImage && fileStat.size > 10 * 1024 * 1024;
      if (isMemDump) {
        try {
          console.error(`[WORKER]   === MEMORY ===`);
          const memResult = analyzeMemoryDump(filePath);
          if (memResult.osInfo) allTimelineEvents.push({ id: `evt-mem-${++eventId}`, timestamp: new Date().toISOString(), action: 'file_opened', entity: memResult.osInfo.osName || 'Unknown', description: `OS: ${memResult.osInfo.osName}`, source: `Volatility3: ${fileName}`, confidence: 0.95, severity: 'benign', metadata: memResult.osInfo, relatedEvents: [] });
          if (memResult.processes?.length) {
            for (const proc of memResult.processes.slice(0, 100)) {
              allNodes.push({ id: `proc-${proc.pid}-${fileName}`, type: 'process', label: `${proc.name} (PID ${proc.pid})`, properties: { pid: proc.pid, ppid: proc.ppid } });
            }
            const susProcs = memResult.processes.filter(p => /password|credential|inject|hook|keylog|rootkit/i.test(p.commandLine || ''));
            for (const sp of susProcs) allFindings.push({ id: `find-mem-${++findingId}`, severity: 'critical', category: 'Memory', title: `Suspicious: ${sp.name}`, description: sp.commandLine, evidence: fileName, timestamp: new Date().toISOString(), relatedArtifacts: [fileName], confidence: 0.85, recommendation: 'Investigate.' });
          }
          if (memResult.hiddenProcesses?.length) allFindings.push({ id: `find-mem-h-${++findingId}`, severity: 'critical', category: 'Memory', title: `${memResult.hiddenProcesses.length} hidden processes`, description: 'Possible rootkit.', evidence: fileName, timestamp: new Date().toISOString(), relatedArtifacts: [fileName], confidence: 0.95 });
          if (memResult.networkConnections?.length) {
            for (const conn of memResult.networkConnections.slice(0, 50)) allNodes.push({ id: `net-${conn.remoteIp}-${fileName}`, type: 'ip', label: `${conn.remoteIp}:${conn.remotePort}`, properties: { pid: conn.pid } });
          }
          for (const sf of (memResult.suspiciousFindings || [])) allFindings.push({ id: `find-vol-${++findingId}`, severity: sf.severity, category: 'Memory', title: sf.title, description: sf.description, evidence: fileName, timestamp: new Date().toISOString(), relatedArtifacts: [fileName], confidence: 0.8 });
        } catch (e) { console.warn(`[WORKER]   Volatility3: ${e.message}`); }
      }

      // === PCAP ===
      const isPCAP = ['.pcap', '.pcapng', '.cap'].some(e => ext === e) || fileAnalysis.magicType === 'network_capture';
      if (isPCAP) {
        try {
          console.error(`[WORKER]   === PCAP ===`);
          const pcapResult = analyzePCAP(filePath);
          for (const dns of (pcapResult.dnsQueries || []).slice(0, 100)) {
            allNodes.push({ id: `dns-${dns.domain}-${fileName}`, type: 'domain', label: dns.domain, properties: { ip: dns.resolvedIp } });
            allTimelineEvents.push({ id: `evt-dns-${++eventId}`, timestamp: new Date().toISOString(), action: 'network_connection', entity: dns.domain, description: `DNS: ${dns.domain} → ${dns.resolvedIp}`, source: `TShark: ${fileName}`, confidence: 0.95, severity: 'benign', relatedEvents: [] });
          }
          for (const http of (pcapResult.httpRequests || []).slice(0, 100)) {
            allTimelineEvents.push({ id: `evt-http-${++eventId}`, timestamp: new Date().toISOString(), action: 'web_page_visited', entity: `${http.host}${http.uri}`, description: `HTTP: ${http.host}${http.uri}`, source: `TShark: ${fileName}`, confidence: 0.95, severity: 'benign', relatedEvents: [] });
          }
          for (const sf of (pcapResult.suspiciousFindings || [])) allFindings.push({ id: `find-pcap-${++findingId}`, severity: sf.severity, category: 'Network', title: sf.title, description: sf.description, evidence: fileName, timestamp: new Date().toISOString(), relatedArtifacts: [fileName], confidence: 0.8 });
        } catch (e) { console.warn(`[WORKER]   TShark: ${e.message}`); }
      }

      // === ARCHIVE ===
      const isArchive = ['.zip', '.7z', '.tar', '.gz', '.rar'].some(e => ext === e) || fileAnalysis.magicType === 'archive';
      if (isArchive && !isImage) {
        try {
          console.error(`[WORKER]   === ARCHIVE ===`);
          const extractDir = `/tmp/recon-x/extracted/${basename(caseDir)}/${fileName}`;
          const archResult = extractAndAnalyzeArchive(filePath, extractDir);
          for (const ef of (archResult.extractedFiles || []).slice(0, 200)) {
            allTimelineEvents.push({ id: `evt-arch-${++eventId}`, timestamp: new Date().toISOString(), action: 'file_opened', entity: ef.name, description: `Extracted: ${ef.name} (${formatSize(ef.size)})`, source: `Archive: ${fileName}`, confidence: 0.9, severity: ef.suspicious ? 'suspicious' : 'benign', metadata: { hash: ef.hash }, relatedEvents: [] });
          }
          for (const sf of (archResult.suspiciousFindings || [])) allFindings.push({ id: `find-arch-${++findingId}`, severity: sf.severity, category: 'Archive', title: sf.title, description: sf.description, evidence: fileName, timestamp: new Date().toISOString(), relatedArtifacts: [fileName], confidence: 0.8 });
        } catch (e) { console.warn(`[WORKER]   Archive: ${e.message}`); }
      }

      // === REGISTRY ===
      const isRegistry = ['.reg', '.hive'].some(e => ext === e) || fileAnalysis.magicType === 'registry_hive' || /ntuser\.dat|sam$|system$|software$|security$/i.test(basename(filePath));
      if (isRegistry) {
        try {
          console.error(`[WORKER]   === REGISTRY ===`);
          const regResult = analyzeRegistryHive(filePath);
          if (regResult.runKeys?.length) allFindings.push({ id: `find-reg-run-${++findingId}`, severity: 'highly_suspicious', category: 'Registry', title: `${regResult.runKeys.length} Run keys`, description: regResult.runKeys.map(r => `${r.key}: ${r.value}`).join('\n'), evidence: fileName, timestamp: new Date().toISOString(), relatedArtifacts: [fileName], confidence: 0.9 });
          for (const usb of (regResult.usbDevices || [])) allTimelineEvents.push({ id: `evt-usb-${++eventId}`, timestamp: usb.lastWriteTime || new Date().toISOString(), action: 'usb_connected', entity: usb.deviceName || 'USB', description: `USB: ${usb.deviceName}`, source: `Registry: ${fileName}`, confidence: 0.85, severity: 'benign', relatedEvents: [] });
          for (const sf of (regResult.suspiciousFindings || [])) allFindings.push({ id: `find-reg-${++findingId}`, severity: sf.severity, category: 'Registry', title: sf.title, description: sf.description, evidence: fileName, timestamp: new Date().toISOString(), relatedArtifacts: [fileName], confidence: 0.8 });
        } catch (e) { console.warn(`[WORKER]   Registry: ${e.message}`); }
      }

      // === PDF ===
      if (ext === '.pdf') {
        try {
          console.error(`[WORKER]   === PDF ===`);
          const pdfResult = analyzePDF(filePath);
          if (pdfResult.hasJS) allFindings.push({ id: `find-pdf-js-${++findingId}`, severity: 'critical', category: 'PDF', title: 'JavaScript in PDF', description: 'Embedded JS — exploit risk.', evidence: fileName, timestamp: new Date().toISOString(), relatedArtifacts: [fileName], confidence: 0.9 });
          if (pdfResult.hasActions) allFindings.push({ id: `find-pdf-act-${++findingId}`, severity: 'highly_suspicious', category: 'PDF', title: 'Auto-actions in PDF', description: `${pdfResult.actions?.length || 0} launch/open actions.`, evidence: fileName, timestamp: new Date().toISOString(), relatedArtifacts: [fileName], confidence: 0.85 });
          if (pdfResult.hasEmbeddedFiles) allFindings.push({ id: `find-pdf-emb-${++findingId}`, severity: 'suspicious', category: 'PDF', title: 'Embedded files in PDF', description: 'Possible malware payload.', evidence: fileName, timestamp: new Date().toISOString(), relatedArtifacts: [fileName], confidence: 0.75 });
        } catch (e) { console.warn(`[WORKER]   PDF: ${e.message}`); }
      }

      // === EXIFTOOL (images) ===
      if (isImage) {
        try {
          const exifResult = analyzeWithExifTool(filePath);
          if (exifResult.gpsCoordinates) allFindings.push({ id: `find-exif-${++findingId}`, severity: 'suspicious', category: 'EXIF', title: `GPS: ${exifResult.gpsCoordinates.latitude}, ${exifResult.gpsCoordinates.longitude}`, description: `Camera: ${exifResult.cameraInfo?.make || ''} ${exifResult.cameraInfo?.model || ''}`, evidence: fileName, timestamp: new Date().toISOString(), relatedArtifacts: [fileName], confidence: 0.9 });
          for (const sf of (exifResult.suspiciousFindings || [])) allFindings.push({ id: `find-exif2-${++findingId}`, severity: sf.severity, category: 'EXIF', title: sf.title, description: sf.description, evidence: fileName, timestamp: new Date().toISOString(), relatedArtifacts: [fileName], confidence: 0.8 });
        } catch (e) { console.warn(`[WORKER]   ExifTool: ${e.message}`); }
      }

      // === BINWALK ===
      if (isBinary && !isDiskImage && !isSQLite && !isPCAP) {
        try {
          const bwResult = analyzeWithBinwalk(filePath);
          if (bwResult.embeddedFiles?.length) allFindings.push({ id: `find-bw-${++findingId}`, severity: 'suspicious', category: 'Binwalk', title: `${bwResult.embeddedFiles.length} embedded files`, description: bwResult.embeddedFiles.slice(0, 10).map(f => `${f.description} at ${f.offset}`).join('\n'), evidence: fileName, timestamp: new Date().toISOString(), relatedArtifacts: [fileName], confidence: 0.8 });
          for (const sf of (bwResult.suspiciousFindings || [])) allFindings.push({ id: `find-bw2-${++findingId}`, severity: sf.severity, category: 'Binwalk', title: sf.title, description: sf.description, evidence: fileName, timestamp: new Date().toISOString(), relatedArtifacts: [fileName], confidence: 0.8 });
        } catch (e) { console.warn(`[WORKER]   Binwalk: ${e.message}`); }
      }

      // Accumulate keywords
      for (const kr of keywordResults) {
        allKeywordResults.push({
          keyword: kr.keyword,
          matches: kr.matches.map(m => ({ file: m.file || fileName, line: m.line || 0, context: m.context, source: m.source || fileName })),
          totalMatches: kr.totalMatches,
        });
      }

      // Timeline from logs
      for (const evt of logEvents) {
        allTimelineEvents.push({
          id: `evt-real-${++eventId}`, timestamp: evt.timestamp.toISOString(),
          action: evt.action, entity: evt.entity, description: evt.description.substring(0, 300),
          source: evt.source, confidence: evt.confidence, severity: evt.severity,
          metadata: { raw: evt.raw.substring(0, 200) }, relatedEvents: [],
        });
      }

      // Timeline from browser history
      if (sqliteAnalysis && sqliteAnalysis.history.length > 0) {
        for (const entry of sqliteAnalysis.history) {
          allTimelineEvents.push({
            id: `evt-real-${++eventId}`, timestamp: entry.lastVisitTime || new Date().toISOString(),
            action: 'web_page_visited', entity: entry.url.substring(0, 150),
            description: entry.title || entry.url, source: `${fileName} (history)`,
            confidence: 0.95, severity: 'benign',
            metadata: { visitCount: entry.visitCount }, relatedEvents: [],
          });
        }
      }

      // Timeline from downloads
      if (sqliteAnalysis && sqliteAnalysis.downloads.length > 0) {
        for (const dl of sqliteAnalysis.downloads) {
          allTimelineEvents.push({
            id: `evt-real-${++eventId}`, timestamp: dl.startTime || new Date().toISOString(),
            action: 'file_downloaded', entity: dl.targetPath || dl.url,
            description: `Downloaded: ${dl.url.substring(0, 200)}`, source: `${fileName} (downloads)`,
            confidence: 0.95, severity: dl.totalBytes > 10 * 1024 * 1024 ? 'suspicious' : 'benign',
            metadata: { size: dl.totalBytes }, relatedEvents: [],
          });
        }
      }

      // Suspicious URLs
      if (sqliteAnalysis && sqliteAnalysis.suspiciousUrls.length > 0) {
        for (const su of sqliteAnalysis.suspiciousUrls) {
          allFindings.push({ id: `find-real-${++findingId}`, severity: 'highly_suspicious', category: 'Browser Activity', title: `Suspicious URL: ${su.url.substring(0, 100)}`, description: `${su.reason}. "${su.title}"`, evidence: fileName, timestamp: new Date().toISOString(), relatedArtifacts: [fileName], confidence: 0.9 });
        }
      }

      // Suspicious from file analysis
      if (fileAnalysis.isSuspicious) {
        for (const reason of fileAnalysis.suspiciousReasons) {
          allFindings.push({
            id: `find-real-${++findingId}`,
            severity: (reason.includes('encrypted') || reason.includes('malware')) ? 'critical' : (reason.includes('high entropy') || reason.includes('packed')) ? 'highly_suspicious' : 'suspicious',
            category: isDiskImage ? 'Disk Image' : 'File Analysis', title: `${fileName}: ${reason}`,
            description: `${reason}. Entropy: ${fileAnalysis.entropy} (${fileAnalysis.entropyLevel}).`,
            evidence: fileName, timestamp: new Date().toISOString(), relatedArtifacts: [fileName], confidence: 0.85,
          });
        }
      }

      // Image suspicious
      if (imageAnalysis?.isSuspicious) {
        for (const reason of imageAnalysis.suspiciousReasons) {
          allFindings.push({ id: `find-real-${++findingId}`, severity: reason.includes('GPS') ? 'suspicious' : 'highly_suspicious', category: 'Image Analysis', title: `Image ${fileName}: ${reason}`, description: `${imageAnalysis.width}x${imageAnalysis.height}. ${reason}`, evidence: fileName, timestamp: new Date().toISOString(), relatedArtifacts: [fileName], confidence: 0.8 });
        }
      }

      // Store processed file
      processedFiles.push({
        path: filePath, name: fileName, size: fileStat.size, hash,
        fileType: ext.replace('.', '') || 'unknown',
        magicType: fileAnalysis.magicType, magicDescription: fileAnalysis.magicDescription,
        entropy: fileAnalysis.entropy, entropyLevel: fileAnalysis.entropyLevel,
        isSuspicious: fileAnalysis.isSuspicious, suspiciousReasons: fileAnalysis.suspiciousReasons,
        isImage, isLog: ext === '.log' || ext === '.txt', isText, isBinary, isSQLite, isDiskImage,
        analysis: fileAnalysis, strings: extractedStrings, logEvents, imageAnalysis, sqliteAnalysis,
        keywordResults, diskImageInfo,
      });

      // Add evidence and custody nodes
      allNodes.push({ id: `node-${fileName}`, type: 'file', label: fileName, properties: { size: fileStat.size, hash, type: fileAnalysis.magicType } });
      if (isSQLite) allNodes.push({ id: `node-sql-${fileName}`, type: 'database', label: `${fileName} (SQLite)`, properties: { tables: sqliteAnalysis?.tables || [] } });
      allEdges.push({ source: 'case-root', target: `node-${fileName}`, relation: 'contains', weight: 1 });

    } catch (fileError) {
      console.error(`[WORKER] ERROR processing ${fileName}:`, fileError.message);
      processedFiles.push({
        path: filePath, name: fileName, size: 0, hash: 'error',
        fileType: 'error', magicType: 'unknown', magicDescription: 'Error',
        entropy: 0, entropyLevel: 'low', isSuspicious: false, suspiciousReasons: ['Processing error'],
        isImage: false, isLog: false, isText: false, isBinary: true, isSQLite: false, isDiskImage: false,
        analysis: null, strings: [], logEvents: [], imageAnalysis: null, sqliteAnalysis: null, keywordResults: [], diskImageInfo: null,
      });
    }
  }

  // ─── Heatmap ───
  const heatmap = [];
  const hourMap = new Array(24).fill(0);
  for (const evt of allTimelineEvents) {
    try {
      const d = new Date(evt.timestamp);
      if (!isNaN(d.getTime())) hourMap[d.getHours()]++;
    } catch { /* skip */ }
  }
  for (let h = 0; h < 24; h++) {
    heatmap.push({ hour: h, count: hourMap[h] });
  }

  // Extract IOCs from all evidence
  console.log('[WORKER] Extracting IOCs...');
  const stringsForIOC = [];
  const textForIOC = [];
  for (const fa of processedFiles) {
    try {
      const str = extractStrings(fa.filePath, 6);
      stringsForIOC.push(str);
    } catch { stringsForIOC.push([]); }
    try {
      const txt = safeReadText(fa.filePath);
      textForIOC.push(isTextFile(txt) ? txt : '');
    } catch { textForIOC.push(''); }
  }
  const extractedIOCs = extractIOCsFromAllEvidence(processedFiles, stringsForIOC, textForIOC);
  console.error(`[WORKER] Extracted ${extractedIOCs.length} IOCs`);

  // ─── Build final result ───
  const allTimestamps = allTimelineEvents.map(e => new Date(e.timestamp).getTime()).filter(t => !isNaN(t));
  const timeRange = allTimestamps.length > 0
    ? { start: new Date(Math.min(...allTimestamps)).toISOString(), end: new Date(Math.max(...allTimestamps)).toISOString() }
    : { start: new Date().toISOString(), end: new Date().toISOString() };

  const catCount = {};
  for (const f of allFindings) { catCount[f.category] = (catCount[f.category] || 0) + 1; }
  const topCategories = Object.entries(catCount).sort((a, b) => b[1] - a[1]).map(([category, count]) => ({ category, count }));

  const result = {
    caseId: basename(caseDir),
    caseInfo,
    evidence: processedFiles.map(f => ({
      id: f.name, caseId: basename(caseDir), name: f.name, type: 'filesystem',
      path: f.path, size: f.size, hash: f.hash, status: 'analyzed',
      uploadedAt: new Date().toISOString(), analyzedAt: new Date().toISOString(),
    })),
    processedFiles,
    timeline: allTimelineEvents,
    rewindSequence: allTimelineEvents.slice(0, 100).reverse().map((e, i) => ({
      id: `rewind-${i}`, timestamp: e.timestamp, event: e.action, entity: e.entity,
      description: e.description, source: e.source, severity: e.severity,
    })),
    suspiciousFindings: allFindings,
    correlations: {
      nodes: [{ id: 'case-root', type: 'case', label: caseInfo.name, properties: {} }, ...allNodes],
      edges: allEdges,
    },
    heatmap,
    keywordResults: allKeywordResults,
    iocs: extractedIOCs,
    geoIPResults: [],
    custody: allCustody,
    stats: {
      totalEvents: allTimelineEvents.length,
      suspiciousCount: allFindings.filter(f => f.severity === 'suspicious').length,
      criticalCount: allFindings.filter(f => f.severity === 'critical').length,
      timeRange,
      topCategories,
      filesProcessed: processedFiles.length,
      filesSuspicious: processedFiles.filter(f => f.isSuspicious).length,
      totalStrings: processedFiles.reduce((sum, f) => sum + f.strings.length, 0),
      keywordsFound: allKeywordResults.reduce((sum, r) => sum + r.totalMatches, 0),
    },
  };

  const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
  console.error(`[WORKER] Analysis complete in ${elapsed}s. Events: ${allTimelineEvents.length}, Findings: ${allFindings.length}`);

  // Output JSON to stdout
  console.log('---JSON-RESULT-START---');
  console.log(JSON.stringify(result));
  console.log('---JSON-RESULT-END---');
}

main().catch(err => {
  console.error('[WORKER] Fatal error:', err.message);
  process.exit(1);
});
